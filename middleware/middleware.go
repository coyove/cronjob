package middleware

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/coyove/cronjob/common"
	"github.com/coyove/cronjob/common/logs"
	"github.com/coyove/cronjob/dal"
	"github.com/coyove/cronjob/ik"
	"github.com/coyove/cronjob/model"
	"github.com/gin-gonic/gin"
)

func Header(g *gin.Context) {
	tok, _ := g.Cookie("id")
	u, _ := dal.GetUserByToken(tok, false)
	if u != nil {
		g.Set("user", u)
		dal.MarkUserActive(u.ID)
	}

	if g.Request.Method == "GET" {
		engine.HTMLRender.Instance("header.html", struct {
			User *model.User
		}{u}).Render(g.Writer)
	}

	g.Next()
}

func mwRenderPerf(g *gin.Context) {
	ip := net.ParseIP(g.ClientIP())
	if ip == nil {
		g.String(403, "Invalid IP: ["+g.ClientIP()+"]")
		return
	}

	if ip.To4() != nil {
		ip = ip.To4()
	}

	for _, subnet := range common.Cfg.IPBlacklistParsed {
		if subnet.Contains(ip) {
			g.AbortWithStatus(403)
			return
		}
	}

	start := time.Now()

	g.Set("ip", ip)
	g.Set("req-start", start)
	g.Next()
	msec := time.Since(start).Nanoseconds() / 1e6

	// if msec > Survey.Max {
	// 	Survey.Max = msec
	// }
	// atomic.AddInt64(&Survey.Written, int64(g.Writer.Size()))

	x := g.Writer.Header().Get("Content-Type")
	if strings.HasPrefix(x, "text/html") && g.Writer.Header().Get("X-Reply") != "true" {
		engine.HTMLRender.Instance("footer.html", struct {
			Render int64
			User   *model.User
		}{msec, nil}).Render(g.Writer)
	}
}

func mwIPThrot(g *gin.Context) {
	if g.Request.Method == "POST" && common.Cfg.ReadOnly {
		g.String(200, "retryable/read-only")
		g.Abort()
		return
	}

	if g.Request.Method != "POST" || strings.HasPrefix(g.Request.URL.Path, "/api/") {
		g.Set("ip-ok", true)
		g.Next()
		return
	}

	ip := g.MustGet("ip").(net.IP).String()
	lastaccess, ok := ik.Dedup.Get(ip)

	if !ok {
		ik.Dedup.Add(ip, time.Now())
		g.Set("ip-ok", true)
		goto NEXT
	} else {
		t, _ := lastaccess.(time.Time)
		diff := time.Since(t).Seconds()

		if diff > float64(common.Cfg.Cooldown) {
			ik.Dedup.Add(ip, time.Now())
			g.Set("ip-ok", true)
			goto NEXT
		}

		g.Set("ip-ok", false)
		g.Set("ip-ok-remain", diff)
	}
NEXT:
	g.Next()
	if g.GetBool("clear-ip-throt") {
		ik.Dedup.Remove(ip)
	}
}

func New(prod bool) *gin.Engine {
	if prod && os.Getenv("CW") != "0" {
		gin.SetMode(gin.ReleaseMode)

		gin.DefaultWriter = ioutil.Discard
		gin.DefaultErrorWriter = logs.New(common.Cfg.CwRegion, common.Cfg.DyAccessKey, common.Cfg.DySecretKey, "iis", "gin")
	} else {
		gin.DefaultErrorWriter = io.MultiWriter(logs.New(common.Cfg.CwRegion, common.Cfg.DyAccessKey, common.Cfg.DySecretKey, "iis", "gin"), os.Stdout)
	}

	log.SetOutput(gin.DefaultErrorWriter)
	log.SetFlags(log.Lshortfile | log.Ltime | log.Ldate)

	r := gin.New()
	r.Use(
		gin.Recovery(),
		mwRenderPerf,
		mwIPThrot,
		RequestSizeLimiter(int64(common.Cfg.MaxRequestSize)*1024*1024),
		errorHandling,
	)

	// loadTrafficCounter()

	engine = r
	return r
}
