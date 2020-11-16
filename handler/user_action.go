package handler

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/arangodb/go-driver"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/coyove/cronjob/common"
	"github.com/coyove/cronjob/dal"
	"github.com/coyove/cronjob/ik"
	"github.com/coyove/cronjob/model"
	"github.com/gin-gonic/gin"
)

func APISignup(g *gin.Context) {
	var (
		email    = common.SoftTrunc(g.PostForm("email"), 80)
		password = common.SoftTrunc(g.PostForm("password"), 30)
	)

	parts := strings.Split(email, "@")
	throw(len(parts) != 2, "invalid_email")
	id := parts[0]

	throw(len(id) < 3 || len(password) < 3, "id_too_short")
	throw(checkCaptcha(g), "")
	throw(strings.HasPrefix(strings.ToLower(id), "admin"), "duplicated_id")

	u, err := dal.Signup(id, email, password, hashIP(g), g.Request.UserAgent())
	if driver.IsConflict(err) {
		u, _ := dal.GetUser(id)
		throw(true, common.IfString(u != nil, "duplicated_id", "duplicated_email"))
	} else {
		throw(err, "internal_error")
	}

	tok := ik.MakeUserToken(u)
	g.SetCookie("id", tok, 365*86400, "", "", false, false)
	okok(g)
}

func APILogin(g *gin.Context) {
	throw(checkIP(g), "")

	u, _ := dal.GetUser(common.SoftTrunc(g.PostForm("username"), 64))
	throw(u, "invalid_id_password")
	throw(u.PassHash != common.HashPassword(g.PostForm("password")), "invalid_id_password")

	u, err := dal.UpdateUserField(u.ID, "TLogin", uint32(time.Now().Unix()))
	throw(err, "internal_error")

	dal.UpdateLoginIP(u.ID, hashIP(g), g.Request.UserAgent())

	tok := ik.MakeUserToken(u)
	ttl := common.IfInt(g.PostForm("remember") != "", 365*86400, 0)
	g.SetCookie("id", tok, ttl, "", "", false, false)

	okok(g)
}

func APILogout(g *gin.Context) {
	u := dal.GetUserByContext(g)
	throw(u, "")
	if _, err := dal.UpdateUserField(u.ID, "Session", common.UUID(16)); err != nil {
		log.Println("logout error:", err)
	}
	g.SetCookie("id", ik.MakeUserToken(u), 365*86400, "", "", false, false)
	okok(g)
}

func APILoginRecords(g *gin.Context) {
	u := throw(dal.GetUserByContext(g), "").(*model.User)
	r, err := dal.ListLoginRecords(u.ID)
	throw(err, "")
	g.JSON(200, r)
}

func APIUserKimochi(g *gin.Context) {
	u := throw(dal.GetUserByContext(g), "").(*model.User)

	k, _ := strconv.Atoi(g.PostForm("k"))
	k = common.IfInt(k < 0 || k > 44, 25, k)

	throw(err2(dal.DoUpdateUser(&dal.UpdateUserRequest{ID: u.ID, Kimochi: aws.Uint8(byte(k))})), "")
	okok(g)
}

func APISearch(g *gin.Context) {
	type p struct {
		ID      string
		Display string
		IsTag   bool
	}
	results := []p{}
	// uids, _, _ := model.Search("su", g.PostForm("id"), 0, 10)
	// for i := range uids {
	// 	if u, _ := dal.GetUser(uids[i]); u != nil {
	// 		results = append(results, p{Display: u.DisplayName(), ID: uids[i]})
	// 	}
	// }
	// tags, _, _ := model.Search("st", g.PostForm("id"), 0, 10)
	// for _, t := range tags {
	// 	results = append(results, p{Display: "#" + t, ID: t, IsTag: true})
	// }
	g.JSON(200, results)
}

func APINewCaptcha(g *gin.Context) {
	uuid, challenge := ik.MakeToken(g)
	g.Writer.Header().Add("X-Uuid", uuid)
	g.Writer.Header().Add("X-Challenge", challenge)
	okok(g)
}

func APILike(g *gin.Context) {
	u := throw(dal.GetUserByContext(g), "").(*model.User)
	to := g.PostForm("to")

	throw(checkIP(g), "")
	throw(to == "", "")
	throw(dal.LikeArticle(u, to, g.PostForm("like") != ""), "")
	okok(g)
}

func APIFollowBlock(g *gin.Context) {
}

func APIUpdateUserSettings(g *gin.Context) {
	u := throw(dal.GetUserByContext(g), "").(*model.User)
	switch {
	case g.PostForm("set-name") != "":
		throw(err2(dal.UpdateUserField(u.ID, "Name", common.SoftTrunc(g.PostForm("name"), 16))), "")
	case g.PostForm("set-email") != "":
		throw(err2(dal.UpdateUserField(u.ID, "Email", common.SoftTrunc(g.PostForm("email"), 256))), "")
	case g.PostForm("set-avatar") != "":
		throw(err2(writeAvatar(u, false, g.PostForm("avatar"))), "")
		throw(err2(dal.UpdateUserField(u.ID, "Avatar", uint32(time.Now().Unix()))), "")
	}
	okok(g)
}

func APIUpdateUserPassword(g *gin.Context) {
	u := throw(dal.GetUserByContext(g), "").(*model.User)
	oldPassHash := common.HashPassword(g.PostForm("old-password"))
	throw(oldPassHash != u.PassHash, "old_password_invalid")
	newPass := common.SoftTrunc(g.PostForm("new-password"), 30)
	throw(len(newPass) < 3, "new_password_too_short")
	throw(err2(dal.UpdateUserField(u.ID, "PassHash", common.HashPassword(newPass))), "")
	okok(g)
}

func APIClearInbox(g *gin.Context) {
	u := throw(dal.GetUserByContext(g), "").(*model.User)
	throw(dal.ClearInbox(u.ID), "")
	okok(g)
}
