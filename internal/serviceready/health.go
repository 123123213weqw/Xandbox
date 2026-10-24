package serviceready

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/123123213weqw/Xandbox/internal/strictjson"
)

type health struct {
	Backend         string `json:"backend"`
	Isolation       *bool  `json:"isolation"`
	Authentication  *bool  `json:"authentication"`
	AdmissionOpen   *bool  `json:"admission_open"`
	ProductionReady *bool  `json:"production_ready"`
	Mechanism       string `json:"isolation_mechanism"`
	Message         string `json:"message"`
}

func healthBody(data []byte) error {
	var h health
	if len(data) > 2048 || strictjson.Decode(data, &h) != nil || h.Backend != "firecracker" || h.Isolation == nil || !*h.Isolation || h.Authentication == nil || !*h.Authentication || h.AdmissionOpen == nil || h.ProductionReady == nil || *h.ProductionReady || h.Mechanism != "firecracker-kvm-jailer" || len(h.Message) > 128 {
		return errPolicy
	}
	// A durably drained service must still become available for reads/cleanup.
	// AdmissionOpen=false is not bootstrap failure or permission to resume it.
	return nil
}
func requestHealth(ctx context.Context, conn net.Conn) error {
	used := false
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 4096, ResponseHeaderTimeout: time.Second, DialContext: func(context.Context, string, string) (net.Conn, error) {
		if used {
			return nil, errPolicy
		}
		used = true
		return conn, nil
	}}
	defer t.CloseIdleConnections()
	c := &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://xandbox.local/healthz", nil)
	if e != nil {
		return e
	}
	response, e := c.Do(r)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		return errPolicy
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 2049))
	if e != nil {
		return e
	}
	return healthBody(b)
}
