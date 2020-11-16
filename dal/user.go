package dal

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arangodb/go-driver"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/coyove/cronjob/common"
	"github.com/coyove/cronjob/dal/tagrank"
	"github.com/coyove/cronjob/ik"
	"github.com/coyove/cronjob/model"
	"github.com/gin-gonic/gin"
)

func init() {
	model.DalIsBlocking = IsBlocking
	model.DalIsFollowing = IsFollowing
	model.DalIsFollowingWithAcceptance = IsFollowingWithAcceptance
}

var NotFound = fmt.Errorf("not found")

func closeCursor(c driver.Cursor) {
	if c != nil {
		c.Close()
	}
}

func readOne(c driver.Cursor, err error, v interface{}) error {
	if err != nil {
		return err
	}
	defer closeCursor(c)
	if !c.HasMore() {
		return NotFound
	}
	_, err = c.ReadDocument(nil, v)
	return err
}

func readMulti(c driver.Cursor, err error, t interface{}) error {
	if err != nil {
		return err
	}
	defer closeCursor(c)
	x := reflect.ValueOf(t)
	for c.HasMore() {
		v := reflect.New(x.Type().Elem().Elem().Elem()) // *[]*t -> []*t -> *t -> t
		if _, err := c.ReadDocument(nil, v.Interface()); err != nil {
			_, fn, line, _ := runtime.Caller(1)
			return fmt.Errorf("ReadMulti %v (%s:%d): %v", x.Type().Elem(), filepath.Base(fn), line, err)
		}
		x.Elem().Set(reflect.Append(x.Elem(), v))
	}
	return nil
}

func GetUser(id string) (*model.User, error) {
	p := common.IfString(!strings.Contains(id, "@"), "_key", "Email")
	c, err := m.adb.Query(nil, "for u in user filter u."+p+" == @id return u", map[string]interface{}{"id": id})
	u := &model.User{}
	return u, readOne(c, err, u)
}

func WeakGetUser(id string) (*model.User, error) {
	return GetUser(id)
}

func Signup(id, email, password, ip, ua string) (*model.User, error) {
	u := &model.User{
		ID:       id,
		Name:     id,
		Email:    email,
		Session:  common.UUID(16),
		PassHash: common.HashPassword(password),
		TSignup:  uint32(time.Now().Unix()),
		TLogin:   uint32(time.Now().Unix()),
	}
	_, err := m.user.CreateDocument(nil, u)
	if driver.IsConflict(err) {
		if u2, _ := GetUser(id); u2 != nil {
			u.ID = common.SafeStringForCompressString(u.Email)
			u.Name = u.ID
			_, err = m.user.CreateDocument(nil, u)
		}
	}
	if err == nil {
		go UpdateLoginIP(id, ip, ua)
	}
	return u, err
}

func UpdateLoginIP(id, ip, userAgent string) {
	_, err := m.userLoginRecord.CreateDocument(nil, &model.UserLoginRecord{
		ID:        id,
		IP:        ip,
		UserAgent: userAgent,
		Time:      uint32(time.Now().Unix()),
	})
	if err != nil {
		log.Println("UpdateLogin:", err)
	}
}

func ListLoginRecords(id string) ([]*model.UserLoginRecord, error) {
	c, err := m.adb.Query(nil, "for r in user_login_record filter r.ID == @id sort r.Time desc limit 0, 10 return r",
		map[string]interface{}{"id": id})
	var x []*model.UserLoginRecord
	err = readMulti(c, err, &x)
	return x, err
}

func UpdateUserField(id string, field string, value interface{}) (*model.User, error) {
	c, err := m.adb.Query(nil, "for u in user update { _key: @id, "+field+": @value } in user return NEW",
		map[string]interface{}{"id": id, "value": value})
	u := &model.User{}
	return u, readOne(c, err, u)
}

func SendPrivateMessage(msg *model.UserInboxMessage) (string, error) {
	msg.ID = ""
	msg.Read = false
	msg.Dismissed = false
	meta, err := m.userInbox.CreateDocument(nil, msg)
	if err == nil {
		msg.ID = meta.Key
	}
	return msg.ID, err
}

func GetUserUnreads(id string) (int, error) {
	c, err := m.adb.Query(nil, "for m in user_inbox filter m.To == @id && !m.Read && !m.Dismissed "+
		"collect with count into unreads return unreads", map[string]interface{}{"id": id})
	var unreads int
	err = readOne(c, err, &unreads)
	return unreads, err
}

func ListUserInboxOrSent(
	mailbox string,
	id string,
	byAnotherId string,
	byNewerThan uint32,
	byOlderThan uint32,
	byTag string,
	desc bool, offset, count int) ([]*model.UserInboxMessage, int64, error) {

	defer common.WatchTime(time.Now(), "ListUserInboxOrSent", mailbox, "of", id, offset, count)

	q := "for m in user_inbox filter m.To == @id && %v && !m.Dismissed"
	if mailbox == "sent" {
		q = "for m in user_inbox filter m.From == @id && %v"
	}
	q += " sort m.Time " + common.IfString(desc, "desc", "") + " limit @offset, @count return m"

	switch {
	case byAnotherId != "":
		q = fmt.Sprintf(q, "m."+common.IfString(mailbox == "sent", "To", "From")+" == "+strconv.Quote(byAnotherId))
	case byOlderThan > 0 && byNewerThan > 0:
		q = fmt.Sprintf(q, "m.Time >= "+u32toa(byOlderThan)+" && m.Time <= "+u32toa(byNewerThan))
	case byOlderThan > 0:
		q = fmt.Sprintf(q, "m.Time >= "+u32toa(byOlderThan))
	case byNewerThan > 0:
		q = fmt.Sprintf(q, "m.Time <= "+u32toa(byNewerThan))
	case byTag != "":
		q = fmt.Sprintf(q, "m.Tag == "+strconv.Quote(byTag))
	default:
		q = fmt.Sprintf(q, "true")
	}

	ctx := driver.WithQueryFullCount(context.TODO())
	c, err := m.adb.Query(ctx, q, map[string]interface{}{
		"id":     id,
		"offset": offset,
		"count":  count,
	})
	var x []*model.UserInboxMessage
	err = readMulti(c, err, &x)
	return x, c.Statistics().FullCount(), err
}

func DismissUserInbox(id, from string) error {
	c, err := m.adb.Query(nil, "for m in user_inbox filter m.To == @to && "+
		common.IfString(from != "", "m.From == @from", "@from == @from")+" update m with { Dismissed: true } in user_inbox",
		map[string]interface{}{"to": id, "from": from})
	closeCursor(c)
	return err
}

func DismissUserInboxByMsgId(id string) error {
	c, err := m.adb.Query(nil, "for m in user_inbox filter m._key == @id update m with { Dismissed: true } in user_inbox",
		map[string]interface{}{"id": id})
	closeCursor(c)
	return err
}

func DeleteUserSent(id, to string) error {
	c, err := m.adb.Query(nil, "for m in user_inbox filter m.From == @from && "+
		common.IfString(to != "", "m.To == @to", "@to == @to")+" remove m in user_inbox",
		map[string]interface{}{"from": id, "to": to})
	closeCursor(c)
	return err
}

func DeleteUserSentByMsgId(id string) error {
	_, err := m.userInbox.RemoveDocument(nil, id)
	return err
}

func GetUserByContext(g *gin.Context) *model.User {
	u, _ := GetUserByToken(g.PostForm("api2_uid"), g.GetBool("allow-api"))
	if u != nil && u.Banned {
		return nil
	}
	return u
}

func GetUserByToken(tok string, allowAPI bool) (*model.User, error) {
	id, session, err := ik.ParseUserToken(tok)
	if err != nil {
		return nil, err
	}

	u, err := GetUser(string(id))
	if err != nil {
		return nil, err
	}

	if allowAPI && tok == u.Settings().APIToken {
		u.SetIsAPI(true)
		return u, nil
	}

	if u.Session != string(session) {
		return nil, fmt.Errorf("invalid token session")
	}
	return u, nil
}

func ClearInbox(uid string) error {
	_, err := DoUpdateArticle(&UpdateArticleRequest{
		ID:          ik.NewID(ik.IDInbox, uid).String(),
		ClearNextID: aws.Bool(true),
	})
	return err
}

func MentionUserAndTags(a *model.Article, ids []string, tags []string) error {
	for _, id := range ids {
		if IsBlocking(id, a.Author) {
			return fmt.Errorf("author blocked")
		}

		if GetUserSettings(id).OnlyMyFollowingsCanMention && !IsFollowing(id, a.Author) {
			continue
		}

		if _, _, err := DoInsertArticle(&InsertArticleRequest{
			ID: ik.NewID(ik.IDInbox, id).String(),
			Article: model.Article{
				ID:  ik.NewGeneralID().String(),
				Cmd: model.CmdInboxMention,
				Extras: map[string]string{
					"from":       a.Author,
					"article_id": a.ID,
				},
			},
		}); err != nil {
			return err
		}

		if _, err := DoUpdateUser(&UpdateUserRequest{ID: id, IncDecUnread: aws.Bool(true)}); err != nil {
			return err
		}
	}

	for _, tag := range tags {
		_, root, err := DoInsertArticle(&InsertArticleRequest{
			ID: ik.NewID(ik.IDTag, tag).String(),
			Article: model.Article{
				ID:      ik.NewGeneralID().String(),
				ReferID: a.ID,
				Media:   a.Media,
			},
		})
		if err != nil {
			return err
		}
		// model.IndexTag(tag)
		tagrank.Update(tag, root.CreateTime, root.Replies)
	}
	return nil
}

func FollowUser(from, to string, following bool) (E error) {
	followID := makeFollowID(from, to)
	updated := false
	defer func() {
		if E != nil || !updated {
			return
		}

		go func() {
			DoUpdateUser(&UpdateUserRequest{ID: from, IncDecFollowings: aws.Bool(following)})
			if !strings.HasPrefix(to, "#") {
				notifyNewFollower(from, to, following)

				if toUser, _ := WeakGetUserWithSettings(to); toUser != nil &&
					toUser.FollowApply != 0 &&
					following {
					_, err := WeakGetArticle(makeFollowerAcceptanceID(to, from))
					if err != model.ErrNotExisted {
						return
					}

					AcceptUser(to, from, false)
					DoInsertArticle(&InsertArticleRequest{
						ID: ik.NewID(ik.IDInbox, to).String(),
						Article: model.Article{
							ID:     ik.NewGeneralID().String(),
							Cmd:    model.CmdInboxFwApply,
							Extras: map[string]string{"from": from},
						},
					})
					DoUpdateUser(&UpdateUserRequest{ID: to, IncDecUnread: aws.Bool(true)})
				}
			}
		}()
	}()

	state := strconv.FormatBool(following) + "," + strconv.FormatInt(time.Now().Unix(), 10)
	oldValue, err := DoUpdateArticleExtra(&UpdateArticleExtraRequest{
		ID:            followID,
		SetExtraKey:   to,
		SetExtraValue: state,
	})
	if err != nil {
		if err != model.ErrNotExisted {
			return err
		}
		updated = true
		_, _, err := DoInsertArticle(&InsertArticleRequest{
			ID: ik.NewID(ik.IDFollowing, from).String(),
			Article: model.Article{
				ID:     followID,
				Cmd:    model.CmdFollow,
				Extras: map[string]string{to: state},
			},
			AsFollowingSlot: true,
		})
		return err
	}

	DoUpdateArticleExtra(&UpdateArticleExtraRequest{
		ID:            ik.NewID(ik.IDFollowing, from).String(),
		SetExtraKey:   lastElemInCompID(followID),
		SetExtraValue: "1",
	})

	if !strings.HasPrefix(oldValue, strconv.FormatBool(following)) {
		updated = true
	}
	return nil
}

func notifyNewFollower(from, to string, following bool) (E error) {
	updated, _, err := DoUpdateOrInsertCmdArticle(&UpdateOrInsertCmdArticleRequest{
		ArticleID:          makeFollowedID(to, from),
		ToSubject:          from,
		InsertUnderChainID: ik.NewID(ik.IDFollower, to).String(),
		Cmd:                model.CmdFollowed,
		CmdValue:           strconv.FormatBool(following),
	})
	if err != nil {
		return err
	}
	if updated {
		if _, err := DoUpdateUser(&UpdateUserRequest{ID: to, IncDecFollowers: aws.Bool(following)}); err != nil {
			return err
		}
	}
	return nil
}

func BlockUser(from, to string, blocking bool) (E error) {
	if blocking {
		if err := FollowUser(to, from, false); err != nil {
			log.Println("Block user:", to, "unfollow error:", err)
		}
		if err := AcceptUser(from, to, false); err != nil {
			log.Println("Unaccept user:", to, "unfollow error:", err)
		}
	}

	_, _, err := DoUpdateOrInsertCmdArticle(&UpdateOrInsertCmdArticleRequest{
		ArticleID:          makeBlockID(from, to),
		ToSubject:          to,
		InsertUnderChainID: ik.NewID(ik.IDBlacklist, from).String(),
		Cmd:                model.CmdBlock,
		CmdValue:           strconv.FormatBool(blocking),
	})
	return err
}

func AcceptUser(from, to string, accept bool) (E error) {
	id := makeFollowerAcceptanceID(from, to)
	if accept {
		go func() {
			DoInsertArticle(&InsertArticleRequest{
				ID: ik.NewID(ik.IDInbox, to).String(),
				Article: model.Article{
					ID:     ik.NewGeneralID().String(),
					Cmd:    model.CmdInboxFwAccepted,
					Extras: map[string]string{"from": from},
				},
			})
			DoUpdateUser(&UpdateUserRequest{ID: to, IncDecUnread: aws.Bool(true)})
		}()
	}
	return m.db.Set(id, (&model.Article{
		ID:     id,
		Extras: map[string]string{"accept": strconv.FormatBool(accept)},
	}).Marshal())
}

func LikeArticle(u *model.User, to string, liking bool) (E error) {
	from := u.ID
	updated, inserted, err := DoUpdateOrInsertCmdArticle(&UpdateOrInsertCmdArticleRequest{
		ArticleID:          makeLikeID(from, to),
		InsertUnderChainID: ik.NewID(ik.IDLike, from).String(),
		Cmd:                model.CmdLike,
		ToSubject:          to,
		CmdValue:           strconv.FormatBool(liking),
	})
	if err != nil {
		return err
	}
	if updated {
		go func() {
			a, err := DoUpdateArticle(&UpdateArticleRequest{ID: to, IncDecLikes: aws.Bool(liking)})
			if err != nil {
				log.Println("LikeArticle error:", err)
				return
			}

			if inserted && liking {
				// insert an article into 'from''s timeline
				if !u.Settings().HideLikesInTimeline {
					DoInsertArticle(&InsertArticleRequest{
						ID: ik.NewID(ik.IDAuthor, from).String(),
						Article: model.Article{
							ID:  ik.NewGeneralID().String(),
							Cmd: model.CmdTimelineLike,
							Extras: map[string]string{
								"from":       from,
								"article_id": to,
							},
						},
					})
				}

				// if the author followed 'from', notify the author that his articles has been liked by 'from'
				if IsFollowing(a.Author, from) {
					DoInsertArticle(&InsertArticleRequest{
						ID: ik.NewID(ik.IDInbox, a.Author).String(),
						Article: model.Article{
							ID:  ik.NewGeneralID().String(),
							Cmd: model.CmdInboxLike,
							Extras: map[string]string{
								"from":       from,
								"article_id": to,
							},
						},
					})
					DoUpdateUser(&UpdateUserRequest{ID: a.Author, IncDecUnread: aws.Bool(true)})
				}
			}
		}()
	}
	return nil
}

type FollowingState struct {
	ID          string
	FullUser    *model.User
	Time        time.Time
	Followed    bool
	RevFollowed bool
	Liked       bool
	Blocked     bool
	Accepted    bool
	// Relationship
	CommonFollowing  bool
	TwoHopsFollowing bool
}

func GetRelationList(u *model.User, chain ik.ID, cursor string, n int) ([]FollowingState, string) {
	if cursor == "" {
		a, err := GetArticle(chain.String())
		if err != nil {
			if err != model.ErrNotExisted {
				log.Println("[GetRelationList] Failed to get chain [", chain, "]")
			}
			return nil, ""
		}
		cursor = a.NextID
	}

	res := []FollowingState{}
	start := time.Now()

	for len(res) < n && strings.HasPrefix(cursor, "u/") {
		if time.Since(start).Seconds() > 0.2 {
			log.Println("[GetRelationList] Break out slow walk [", chain.Tag(), "]")
			break
		}

		a, err := GetArticle(cursor)
		if err != nil {
			log.Println("[GetRelationList]", cursor, err)
			break
		}

		s := FollowingState{
			ID:          a.Extras["to"],
			Time:        a.CreateTime,
			Blocked:     a.Extras["block"] == "true",
			RevFollowed: a.Extras["followed"] == "true",
			Liked:       a.Extras["like"] == "true",
		}
		s.FullUser, _ = GetUser(s.ID)

		if chain.Header() == ik.IDFollower && s.RevFollowed {
			s.Followed = IsFollowing(chain.Tag(), s.ID)
			s.RevFollowed, s.Accepted = IsFollowingWithAcceptance(s.ID, u)
		}

		res = append(res, s)
		cursor = a.NextID
	}

	sort.Slice(res, func(i, j int) bool { return res[i].Time.After(res[j].Time) })

	return res, cursor
}

func GetFollowingList(chain ik.ID, cursor string, n int, fulluser bool) ([]FollowingState, string) {
	var idx int
	var flags map[string]string

	if parts := strings.Split(cursor, "~"); len(parts) != 2 {
		// Start from the root article
		master, err := GetArticle(chain.String())
		if err != nil {
			if err != model.ErrNotExisted {
				log.Println("[GetRelationList] Failed to get chain [", chain, "]")
			}
			return nil, ""
		}
		flags = master.Extras
	} else {
		// Parse the cursor and 0 - 255 flags
		idx, _ = strconv.Atoi(parts[0])
		flags = common.Unpack256(parts[1])
		if idx > 255 || idx < 0 || flags == nil {
			return nil, ""
		}
	}

	res := []FollowingState{}
	start := time.Now()

	for who := chain.Tag(); len(res) < n && idx < 256; idx++ {
		if flags[strconv.Itoa(idx)] != "1" {
			continue
		}

		if time.Since(start).Seconds() > 0.2 {
			log.Println("[GetFollowingList] Break out slow walk [", chain.Tag(), "]")
			break
		}

		a, err := GetArticle("u/" + who + "/follow/" + strconv.Itoa(idx))
		if err != nil {
			log.Println("[GetFollowingList]", cursor, err)
			break
		}

		for k, v := range a.Extras {
			p := strings.Split(v, ",")
			if len(p) != 2 {
				continue
			}
			s := FollowingState{
				ID:       k,
				Time:     time.Unix(atoi64(p[1]), 0),
				Followed: atob(p[0]),
				Blocked:  IsBlocking(who, k),
			}
			if fulluser {
				if !strings.HasPrefix(k, "#") {
					s.FullUser, _ = GetUser(k)
				} else {
					s.FullUser = &model.User{ID: k}
				}
				if s.FullUser == nil {
					continue
				}
			}
			res = append(res, s)
		}
	}

	sort.Slice(res, func(i, j int) bool { return res[i].Time.After(res[j].Time) })

	if idx > 255 {
		cursor = ""
	} else {
		cursor = strconv.Itoa(idx) + "~" + common.Pack256(flags)
	}

	return res, cursor
}

func IsFollowing(from, to string) bool {
	p, _ := GetArticle(makeFollowID(from, to))
	return p != nil && strings.HasPrefix(p.Extras[to], "true")
}

func IsFollowingWithAcceptance(from string, to *model.User) (following bool, accepted bool) {
	if from == to.ID {
		return true, true
	}
	if to.FollowApply == 0 {
		// 'to' didn't have the switch on, so no acceptance needed for 'from'
		return IsFollowing(from, to.ID), true
	}
	p, _ := GetArticle(makeFollowID(from, to.ID))
	if p == nil {
		return false, false
	}
	if !strings.HasPrefix(p.Extras[to.ID], "true,") {
		return false, false // didn't follow 'to' at all
	}
	ts, err := strconv.ParseInt(p.Extras[to.ID][5:], 10, 64)
	if err != nil {
		return false, false
	}
	if time.Unix(ts, 0).Before(to.FollowApplyPivotTime()) {
		return true, true // 'from' followed 'to' before 'to' turned on the switch, so 'from' gains acceptance automatically
	}
	accept, _ := GetArticle(makeFollowerAcceptanceID(to.ID, from))
	if accept == nil {
		return true, false
	}
	return true, accept.Extras["accept"] == "true"
}

func IsBlocking(from, to string) bool {
	p, _ := WeakGetArticle(makeBlockID(from, to))
	return p != nil && p.Extras["block"] == "true"
}

func IsLiking(from, to string) bool {
	p, _ := WeakGetArticle(makeLikeID(from, to))
	return p != nil && p.Extras["like"] == "true"
}

func LastActiveTime(uid string) time.Time {
	v, _ := m.activeUsers.Get("u/" + uid + "/last_active")
	t, _ := strconv.ParseInt(string(v), 10, 64)
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(t, 0)
}

func MarkUserActive(uid string) {
	m.cache.Add("u/"+uid+"/last_active", []byte(strconv.FormatInt(time.Now().Unix(), 10)))
}

func CacheGet(key string) (string, bool) {
	v, ok := m.activeUsers.Get(key)
	return string(v), ok
}

func CacheSet(key string, value string) {
	m.activeUsers.Add(key, []byte(value))
}

func WeakGetUserWithSettings(id string) (*model.User, error) {
	panic("getterUser")
}

func getterUser(getter func(string) ([]byte, error), id string) (*model.User, error) {
	panic("getterUser")
}

func GetUserWithSettings(id string) (*model.User, error) {
	panic("getterUser")
}

func GetUserSettings(id string) model.UserSettings {
	panic("getterUser")
}

func WeakGetUserSettings(id string) model.UserSettings {
	panic("getterUser")
}
