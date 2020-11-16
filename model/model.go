package model

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/coyove/cronjob/common"
)

var (
	ErrNotExisted                = errors.New("article not existed")
	Dummy                        = User{_IsYou: true}
	DalIsFollowing               func(string, string) bool
	DalIsBlocking                func(string, string) bool
	DalIsFollowingWithAcceptance func(string, *User) (bool, bool)
)

type Cmd string

const (
	CmdNone            Cmd = ""
	CmdInboxReply          = "inbox-reply"
	CmdInboxMention        = "inbox-mention"
	CmdInboxFwApply        = "inbox-fw-apply"
	CmdInboxFwAccepted     = "inbox-fw-accepted"
	CmdFollow              = "follow"
	CmdFollowed            = "followed"
	CmdBlock               = "block"
	CmdLike                = "like"          // indicate the raw cmd article
	CmdInboxLike           = "inbox-like"    // indicate the notification shown in inbox
	CmdTimelineLike        = "timeline-like" // indicate the notification shown in timeline

	DeletionMarker = "[[b19b8759-391b-460a-beb0-16f5f334c34f]]"
)

const (
	ReplyLockNobody byte = 1 + iota
	ReplyLockFollowingsCan
	ReplyLockFollowingsMentionsCan
	ReplyLockFollowingsFollowersCan

	PostOptionNoMasterTimeline byte = 1
	PostOptionNoTimeline            = 2
	PostOptionNoSearch              = 4
)

type Article struct {
	ID            string            `json:"id"`
	AID           int64             `json:"Ai,omitempty"`
	Replies       int               `json:"rs,omitempty"`
	Likes         int32             `json:"like,omitempty"`
	ReplyLockMode byte              `json:"lm,omitempty"`
	PostOptions   byte              `json:"po,omitempty"`
	NSFW          bool              `json:"nsfw,omitempty"`
	Anonymous     bool              `json:"anon,omitempty"`
	Content       string            `json:"content,omitempty"`
	Media         string            `json:"M,omitempty"`
	Author        string            `json:"author,omitempty"`
	IP            string            `json:"ip,omitempty"`
	CreateTime    time.Time         `json:"create,omitempty"`
	Parent        string            `json:"P,omitempty"`
	ReplyChain    string            `json:"Rc,omitempty"`
	NextReplyID   string            `json:"R,omitempty"`
	NextMediaID   string            `json:"MN,omitempty"`
	NextID        string            `json:"N,omitempty"`
	EOC           string            `json:"EO,omitempty"`
	Cmd           Cmd               `json:"K,omitempty"`
	Extras        map[string]string `json:"X,omitempty"`
	ReferID       string            `json:"ref,omitempty"`
	History       string            `json:"his,omitempty"`

	T_StickOnTop bool `json:"-"`
}

func (a *Article) IsDeleted() bool {
	return a.Content == DeletionMarker
}

func (a *Article) ContentHTML() template.HTML {
	if a.IsDeleted() {
		a.Extras = nil
		return "<span class=deleted></span>"
	}
	return template.HTML(common.SanText(a.Content))
}

func (a *Article) PickNextID(media bool) string {
	if media {
		return a.NextMediaID
	}
	return a.NextID
}

func (a *Article) Marshal() []byte {
	b, _ := json.Marshal(a)
	return b
}

func UnmarshalArticle(b []byte) (*Article, error) {
	a := &Article{}
	err := json.Unmarshal(b, a)
	if a.ID == "" {
		return nil, fmt.Errorf("failed to unmarshal: %q", b)
	}
	return a, err
}

type User struct {
	ID       string `json:"_key"`
	Session  string
	Name     string
	Email    string
	PassHash string
	Banned   bool
	Avatar   uint32
	BgVer    uint32
	TSignup  uint32
	TLogin   uint32
	Unread   uint32
	Extras   map[string]string

	Role         string
	PasswordHash []byte
	CustomName   string `json:"cn"`
	Followers    int32  `json:"F"`
	Followings   int32  `json:"f"`
	DataIP       string `json:"sip"`
	Kimochi      byte   `json:"kmc,omitempty"`
	FollowApply  int32  `json:"fap,omitempty"`

	_IsFollowing            bool
	_IsFollowingNotAccepted bool
	_IsFollowed             bool
	_IsBlocking             bool
	_IsYou                  bool
	_IsInvalid              bool
	_IsAnon                 bool
	_IsAPI                  bool
	_ShowList               byte
	_Settings               UserSettings
}

type UserLoginRecord struct {
	ID        string
	IP        string
	UserAgent string
	Time      uint32
}

type UserInboxMessage struct {
	ID        string
	From, To  string
	Title     string
	Content   string
	Tag       string
	Extras    map[string]string
	Time      uint32
	Read      bool
	Dismissed bool
}

func (u User) Marshal() []byte {
	b, _ := json.Marshal(u)
	return b
}

func (u User) AvatarURL() string {
	if common.Cfg.MediaDomain != "" {
		path := fmt.Sprintf("%s/%016x@%s?q=%d", common.Cfg.MediaDomain, u.IDHash(), u.ID, u.Avatar)
		return path
	} else {
		return fmt.Sprintf("/avatar/%s?q=%d", u.ID, u.Avatar)
	}
}

func (u User) BackgroundURL() string {
	if common.Cfg.MediaDomain != "" {
		path := fmt.Sprintf("%s/%016x@%s?q=%d", common.Cfg.MediaDomain, u.IDHash(), u.ID, u.BgVer)
		return path
	} else {
		return fmt.Sprintf("/avatar/%s?q=%d&bg=1", u.ID, u.BgVer)
	}
}

func (u User) KimochiURL() string {
	return fmt.Sprintf("/s/emoji/emoji%d.png", u.Kimochi)
}

func (u User) DisplayName() string {
	n := u.Name
	if n != u.ID {
		n += "@" + u.ID
	}
	return n
}

func (u User) RecentIPLocation() string {
	if u.Settings().HideLocation {
		return ""
	}
	for _, part := range strings.Split(u.DataIP, ",") {
		part = strings.Trim(strings.TrimSpace(part), "{}")
		if len(part) == 0 {
			continue
		}
		var data = strings.Split(part, "/")
		_, loc := common.LookupIP(data[0])
		return loc
	}
	return ""
}

func (u User) IsFollowing() bool { return u._IsFollowing }

func (u User) IsFollowingNotAccepted() bool { return u._IsFollowingNotAccepted }

func (u User) IsFollowed() bool { return u._IsFollowed }

func (u User) IsBlocking() bool { return u._IsBlocking }

func (u User) IsYou() bool { return u._IsYou }

func (u User) IsInvalid() bool { return u._IsInvalid }

func (u User) IsAnon() bool { return u._IsAnon }

func (u User) IsAPI() bool { return u._IsAPI }

func (u *User) SetInvalid() *User { u._IsInvalid = true; return u }

func (u *User) SetIsAnon(v bool) *User { u._IsAnon = v; return u }

func (u *User) SetIsAPI(v bool) *User { u._IsAPI = v; return u }

func (u User) ShowList() byte { return u._ShowList }

func (u User) Settings() UserSettings { return u._Settings }

func (u *User) Buildup(you *User) {
	following, accepted := DalIsFollowingWithAcceptance(you.ID, u)
	u._IsYou = you.ID == u.ID
	if u._IsYou {
		return
	}
	u._IsFollowing = following
	u._IsFollowingNotAccepted = following && !accepted
	u._IsFollowed = DalIsFollowing(u.ID, you.ID)
	u._IsBlocking = DalIsBlocking(you.ID, u.ID)
}

func (u *User) SetShowList(t byte) { u._ShowList = t }

func (u *User) SetSettings(s UserSettings) { u._Settings = s }

func (u User) JSON() string {
	b, _ := json.MarshalIndent(u, "", "")
	b = bytes.TrimLeft(b, " \r\n\t{")
	b = bytes.TrimRight(b, " \r\n\t}")
	return string(b)
}

func (u User) Signup() time.Time { return time.Unix(int64(u.TSignup), 0) }

func (u User) Login() time.Time { return time.Unix(int64(u.TLogin), 0) }

func (u User) IsMod() bool { return u.Role == "mod" || u.ID == common.Cfg.AdminName }

func (u User) IsAdmin() bool { return u.Role == "admin" || u.ID == common.Cfg.AdminName }

func (u User) IDHash() (hash uint64) {
	x := sha1.Sum([]byte(u.ID))
	return binary.BigEndian.Uint64(x[:])
}

func (u User) FollowApplyPivotTime() time.Time {
	return time.Unix(int64(u.FollowApply), 0)
}

func UnmarshalUser(b []byte) (*User, error) {
	a := &User{}
	err := json.Unmarshal(b, a)
	if a.ID == "" {
		return nil, fmt.Errorf("failed to unmarshal: %q", b)
	}

	// common.AddUserToSearch(a.ID)
	return a, err
}

type UserSettings struct {
	AutoNSFW                   bool   `json:"autonsfw,omitempty"`
	FoldImages                 bool   `json:"foldi,omitempty"`
	OnlyMyFollowingsCanMention bool   `json:"mfcm,omitempty"`
	HideLikesInTimeline        bool   `json:"slit,omitempty"`
	HideLikes                  bool   `json:"hlikes,omitempty"`
	HideLocation               bool   `json:"hl,omitempty"`
	Description                string `json:"desc,omitempty"`
	APIToken                   string `json:"apisess,omitempty"`
}

func (u UserSettings) Marshal() []byte {
	p, _ := json.Marshal(u)
	return p
}

func (u UserSettings) DescHTML() template.HTML {
	return template.HTML(common.SanText(u.Description))
}

// Always return a valid struct, though sometimes being empty
func UnmarshalUserSettings(b []byte) UserSettings {
	a := UserSettings{}
	json.Unmarshal(b, &a)
	return a
}

type Job struct {
	ID                    string `json:"_key"`
	CreatorID             string
	Payload               string
	Result                string
	CreateTime            uint32
	PickedTime            uint32
	ExpectPickedAfterTime uint32
	CancelTime            uint32
	DependJob             string
	Status                int // 0: pending, 1: picked, 2: finished, 3: canceled
}
