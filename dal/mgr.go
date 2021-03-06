package dal

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"strconv"
	"time"

	driver "github.com/arangodb/go-driver"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/coyove/common/lru"
	"github.com/coyove/cronjob/common"
	"github.com/coyove/cronjob/dal/ctr"
	"github.com/coyove/cronjob/dal/kv"
	"github.com/coyove/cronjob/ik"
	"github.com/coyove/cronjob/model"
)

var Masters = 10
var S3 *kv.S3Storage
var Ctr *ctr.Counter

var m struct {
	adb             driver.Database
	user            driver.Collection
	userLoginRecord driver.Collection
	userInbox       driver.Collection
	job             driver.Collection
	weak            *lru.Cache
	cache           *kv.GlobalCache

	db          KeyValueOp
	activeUsers *kv.GlobalCache
}

func Init(dbname string, redisConfig *kv.RedisConfig, arangoDB driver.ClientConfig) {
	// Ctr = ctr.New(100, &ctr.FSBack{Dir: "tmp/ctr"})
	m.cache = kv.NewGlobalCache(redisConfig)
	m.weak = lru.NewCache(1024)

	cli, err := driver.NewClient(arangoDB)
	common.PanicErr(err)

	m.adb, err = cli.Database(nil, dbname)
	if driver.IsNotFound(err) {
		m.adb, err = cli.CreateDatabase(nil, dbname, nil)
	}
	common.PanicErr(err)

	ensureCollection := func(col string, index ...string) driver.Collection {
		c, err := m.adb.Collection(nil, col)
		if driver.IsNotFound(err) {
			c, err = m.adb.CreateCollection(nil, col, nil)
		}
		common.PanicErr(err)
		_, _, err = c.EnsurePersistentIndex(nil, index, &driver.EnsurePersistentIndexOptions{InBackground: true})
		common.PanicErr(err)
		return c
	}

	ensureSearchView := func(col string, allFields bool, fields ...string) {
		name := col + "_search_view"
		_, err := m.adb.View(nil, name)
		if driver.IsNotFound(err) {
			sfields := driver.ArangoSearchFields{}
			for _, f := range fields {
				sfields[f] = driver.ArangoSearchElementProperties{
					Analyzers: []string{"text_zh", "text_en"},
				}
			}
			_, err = m.adb.CreateArangoSearchView(nil, name, &driver.ArangoSearchViewProperties{
				Links: driver.ArangoSearchLinks{
					col: {
						IncludeAllFields: aws.Bool(allFields),
						Fields:           sfields,
					},
				},
			})
		}
		common.PanicErr(err)
	}

	m.user = ensureCollection("user", "Name")
	_, _, err = m.user.EnsurePersistentIndex(nil, []string{"Email"}, &driver.EnsurePersistentIndexOptions{
		InBackground: true,
		Unique:       true,
	})
	common.PanicErr(err)
	ensureSearchView("user", false, "Name", "Description")

	m.userLoginRecord = ensureCollection("user_login_record", "ID")
	m.userInbox = ensureCollection("user_inbox", "From", "To", "Tag")
	m.job = ensureCollection("job", "CreatorID", "Status")
}

func ModKV() KeyValueOp {
	return m.db
}

func MGetArticlesFromCache(keys ...string) map[string]*model.Article {
	if len(keys) > 1024 {
		keys = keys[:1024]
	}
	res := m.activeUsers.MGet(keys...)
	m := map[string]*model.Article{}
	for k, v := range res {
		a, err := model.UnmarshalArticle(v)
		if err == nil {
			m[k] = a
		}
	}
	return m
}

func GetArticle(id string, dontOverrideNextID ...bool) (*model.Article, error) {
	return getterArticle(m.db.Get, id, dontOverrideNextID...)
}

func WeakGetArticle(id string, dontOverrideNextID ...bool) (*model.Article, error) {
	return getterArticle(m.db.WeakGet, id, dontOverrideNextID...)
}

func getterArticle(getter func(string) ([]byte, error), id string, dontOverrideNextID ...bool) (*model.Article, error) {
	if id == "" {
		return nil, fmt.Errorf("empty id")
	}
	p, err := getter(id)
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, model.ErrNotExisted
	}
	a, err := model.UnmarshalArticle(p)
	if err != nil {
		return nil, err
	}
	if a.ReferID == "" {
		return a, nil
	}
	a2, err := getterArticle(getter, a.ReferID)
	if err != nil {
		return nil, err
	}
	if len(dontOverrideNextID) == 1 && dontOverrideNextID[0] {
		return a2, nil
	}
	a2.NextID = a.NextID
	a2.NextMediaID = a.NextMediaID
	return a2, nil
}

func WalkMulti(media bool, n int, cursors ...ik.ID) (a []*model.Article, next []ik.ID) {
	if len(cursors) == 0 {
		return
	}

	showStickOnTop := len(cursors) == 1 && cursors[0].Header() == ik.IDAuthor // show stick-on-top only in single user timeline
	idm := map[string]bool{}
	idmp := map[string]bool{} // dedup map for parent articles
	appendStickOnTop := func(id string) {
		if top, _ := GetArticle(id); top != nil {
			top.T_StickOnTop = true
			a = append(a, top)
			idm[top.ID] = true
		}
	}

	// Quick hack: mget from cache first
	var trykeys []string
	var trykeysIndex []int

	for i, c := range cursors {
		if hdr := c.Header(); hdr == ik.IDAuthor || hdr == ik.IDTag {
			trykeys = append(trykeys, c.String())
			trykeysIndex = append(trykeysIndex, i)
		}
	}
	if len(trykeys) > 0 {
		m := MGetArticlesFromCache(trykeys...)
		count := 0
		for i, k := range trykeys {
			if m[k] == nil {
				continue
			}

			cursors[trykeysIndex[i]] = ik.ParseID(m[k].PickNextID(media))
			count++

			if top := ik.ParseID(m[k].Extras["stick_on_top"]); showStickOnTop && top.Valid() {
				appendStickOnTop(top.String())
			}
		}
	}

	for startTime := time.Now(); len(a) < n; {
		if time.Since(startTime).Seconds() > 1 {
			if len(cursors) < 20 {
				log.Println("[mgr.WalkMulti] Break out slow walk at", cursors)
			} else {
				log.Println("[mgr.WalkMulti] Break out slow walk with big cursors:", len(cursors))
			}
			break
		}

	DEDUP: // not some very good dedup code
		dedup := make(map[ik.ID]bool, len(cursors))
		for i, c := range cursors {
			if dedup[c] {
				cursors = append(cursors[:i], cursors[i+1:]...)
				goto DEDUP
			}
			dedup[c] = true
		}

		sort.Slice(cursors, func(i, j int) bool {
			if ii, jj := cursors[i].Time(), cursors[j].Time(); ii == jj {
				return bytes.Compare(cursors[i].TagBytes(), cursors[j].TagBytes()) < 0
			} else if cursors[i].IsRoot() { // i is bigger than j
				return false
			} else if cursors[j].IsRoot() {
				return true
			} else {
				return ii.Before(jj)
			}
		})

		latest := &cursors[len(cursors)-1]
		if !latest.Valid() {
			break
		}

		p, err := WeakGetArticle(latest.String())
		// Calling WeakGet instead of Get will cause:
		//   1. Deleted article may be reappeared
		//   2. Likes/Replies number may not be accurate, along with other updatable fields
		// If we are deploying IIS on a single machine, none of the above cases will be a problem
		// With distibuted IIS, users may see different results each time they refresh the page

		if err == nil {
			ok := !idm[p.ID] && p.Content != model.DeletionMarker && !latest.IsRoot()
			// 1. 'p' is not duplicated
			// 2. 'p' is not deleted
			// 3. 'p' is not a root article

			if p.Parent == "" && idmp[p.ID] {
				// 4. if 'p' is a top article and has been replied before (presented in 'idmp')
				//    ignore it to clean the timeline a bit
				ok = false
			}

			if showStickOnTop && latest.IsRoot() && p.Extras["stick_on_top"] != "" {
				appendStickOnTop(p.Extras["stick_on_top"])
			}

			if ok {
				a = append(a, p)

				idm[p.ID] = true
				if p.Parent != "" {
					idmp[p.Parent] = true
				}
			}
			*latest = ik.ParseID(p.PickNextID(media))
		} else {
			if err != model.ErrNotExisted {
				log.Println("[mgr.WalkMulti] Failed to get:", latest.String(), err)
			}

			*latest = ik.ID{}
		}
	}

	return a, cursors
}

func WalkReply(n int, cursor string) (a []*model.Article, next string) {
	startTime := time.Now()

	for len(a) < n && cursor != "" {
		if time.Since(startTime).Seconds() > 1 {
			log.Println("[mgr.WalkReply] Break out slow walk at", cursor)
			break
		}

		p, err := GetArticle(cursor)
		if err != nil {
			log.Println("[mgr.WalkReply] Failed to get:", cursor, err)
			break
		}

		if p.Content != model.DeletionMarker {
			a = append(a, p)
		}
		cursor = p.NextReplyID
	}

	return a, cursor
}

func WalkLikes(media bool, n int, cursor string) (a []*model.Article, next string) {
	startTime := time.Now()

	for len(a) < n && cursor != "" {
		if time.Since(startTime).Seconds() > 1 {
			log.Println("[mgr.WalkLikes] Break out slow walk at", cursor)
			break
		}

		p, err := GetArticle(cursor)
		if err != nil {
			log.Println("[mgr.WalkLikes] Failed to get:", cursor, err)
			break
		}

		if p.Extras["like"] == "true" {
			a2, err := GetArticle(p.Extras["to"])
			if err == nil {
				a2.NextID = p.NextID
				a = append(a, a2)
			} else {
				log.Println("[mgr.WalkLikes] Failed to get:", p.Extras["to"], err)
			}
		}

		cursor = p.PickNextID(media)
	}

	return a, cursor
}

func Post(a *model.Article, author *model.User) (*model.Article, error) {
	a.ID = ik.NewGeneralID().String()
	a.Author = author.ID

	if _, _, err := DoInsertArticle(&InsertArticleRequest{
		ID:      ik.NewID(ik.IDAuthor, a.Author).String(),
		Article: *a,
	}); err != nil {
		return nil, err
	}

	go func() {
		if a.PostOptions&model.PostOptionNoMasterTimeline == 0 {
			master := "master"
			if r := rand.Intn(Masters); r > 0 {
				master += strconv.Itoa(r)
			}
			DoInsertArticle(&InsertArticleRequest{
				ID: ik.NewID(ik.IDAuthor, master).String(),
				Article: model.Article{
					ID:      ik.NewGeneralID().String(),
					ReferID: a.ID,
					Media:   a.Media,
				},
			})
		}
		ids, tags := common.ExtractMentionsAndTags(a.Content)
		MentionUserAndTags(a, ids, tags)
	}()

	return a, nil
}

func PostReply(parent string, a *model.Article, author *model.User) (*model.Article, error) {
	p, err := GetArticle(parent)
	if err != nil {
		return nil, err
	}

	if p.ReplyLockMode != 0 && !(p.Author == author.ID || author.IsMod()) {
		// The author himself can reply to his own locked articles
		// And site moderators of course
		can := false
		switch p.ReplyLockMode {
		case model.ReplyLockNobody:
			can = false
		case model.ReplyLockFollowingsCan:
			can = IsFollowing(p.Author, author.ID)
		case model.ReplyLockFollowingsMentionsCan:
			can = IsFollowing(p.Author, author.ID)
			if !can {
				mentions, _ := common.ExtractMentionsAndTags(p.Content)
				for _, m := range mentions {
					if m == author.ID {
						can = true
						break
					}
				}
			}
		case model.ReplyLockFollowingsFollowersCan:
			can = IsFollowing(p.Author, author.ID)
			if !can {
				pauthor, _ := GetUserWithSettings(p.Author)
				if pauthor != nil {
					following, accepted := IsFollowingWithAcceptance(author.ID, pauthor)
					can = following && accepted
				}
			}
		}
		if !can {
			return nil, fmt.Errorf("locked parent")
		}
	}

	if IsBlocking(p.Author, author.ID) {
		if !author.IsMod() {
			return nil, fmt.Errorf("author blocked")
		}
	}

	a.ID = ik.NewGeneralID().String()
	a.Parent = p.ID

	a2, _, err := DoInsertArticle(&InsertArticleRequest{ID: p.ID, Article: *a, AsReply: true})
	if err != nil {
		return nil, err
	}
	a = &a2

	if a.PostOptions&model.PostOptionNoTimeline == 0 {
		// Add reply to its author's timeline
		if _, _, err := DoInsertArticle(&InsertArticleRequest{
			ID:      ik.NewID(ik.IDAuthor, a.Author).String(),
			Article: *a,
		}); err != nil {
			return nil, err
		}
	}

	go func() {
		if p.Content != model.DeletionMarker && a.Author != p.Author {
			if WeakGetUserSettings(p.Author).OnlyMyFollowingsCanMention && !IsFollowing(p.Author, a.Author) {
				return
			}

			if _, _, err := DoInsertArticle(&InsertArticleRequest{
				ID: ik.NewID(ik.IDInbox, p.Author).String(),
				Article: model.Article{
					ID:  ik.NewGeneralID().String(),
					Cmd: model.CmdInboxReply,
					Extras: map[string]string{
						"from":       a.Author,
						"article_id": a.ID,
					},
				},
			}); err != nil {
				log.Println("PostReply", err)
			}

			DoUpdateUser(&UpdateUserRequest{ID: p.Author, IncDecUnread: aws.Bool(true)})
		}
		ids, tags := common.ExtractMentionsAndTags(a.Content)
		MentionUserAndTags(a, ids, tags)
	}()

	return a, nil
}
