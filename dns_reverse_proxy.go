/*
Binary dns_reverse_proxy is a DNS reverse proxy to route queries to DNS servers.

To illustrate, imagine an HTTP reverse proxy but for DNS.
It listens on both TCP/UDP IPv4/IPv6 on specified port.
Since the upstream servers will not see the real client IPs but the proxy,
you can specify a list of IPs allowed to transfer (AXFR/IXFR).

Example usage:
        $ go run dns_reverse_proxy.go -address :53 \
                -default 8.8.8.8:53 \
                -route .example.com.=8.8.4.4:53 \
                -allow-transfer 1.2.3.4,::1

A query for example.net or example.com will go to 8.8.8.8:53, the default.
However, a query for subdomain.example.com will go to 8.8.4.4:53.
*/
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"math/rand"
)

var (
	address   = flag.String("address", ":53", "Address to listen to (TCP and UDP)")
	routeList = flag.String("route", "",
		"List of routes where to send queries (domain=host:port)")
	routes map[string]string

	allowTransfer = flag.String("allow-transfer", "",
		"List of IPs allowed to transfer (AXFR/IXFR)")
	transferIPs  []string
	publicServer = []string{"1.1.1.1:53", "8.8.8.8:53", "8.8.4.4:53", "209.244.0.3", "209.244.0.4", "64.6.64.6", "64.6.65.6",
		"9.9.9.9:53", "149.112.112.112:53", "84.200.69.80:53", "84.200.70.40:53", "8.26.56.26:53", "8.20.247.20:53", "208.67.222.222:53",
		"208.67.220.220", "199.85.126.10:53", "199.85.127.10:53", "81.218.119.11:53", "209.88.198.133:53", "195.46.39.39:53", "195.46.39.40:53",
		"69.195.152.204:53", "23.94.60.240:53", "208.76.50.50:53", "208.76.51.51:53", "216.146.35.35:53", "216.146.36.36:53",
		"37.235.1.174:53", "37.235.1.177:53", "198.101.242.72:53", "23.253.163.53:53", "77.88.8.8:53", "77.88.8.1:53", "91.239.100.100:53",
	}
)

func randomPublicServer() string {
	return publicServer[rand.Intn(len(publicServer))]

}
func main() {
	flag.Parse()
	transferIPs = strings.Split(*allowTransfer, ",")
	routes = make(map[string]string)
	if *routeList != "" {
		for _, s := range strings.Split(*routeList, ",") {
			s := strings.SplitN(s, "=", 2)
			if len(s) != 2 || !validHostPort(s[1]) {
				log.Fatal("invalid -route, must be list of domain=host:port")
			}
			if !strings.HasSuffix(s[0], ".") {
				s[0] += "."
			}
			routes[s[0]] = s[1]
		}
	}

	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}
	dns.HandleFunc(".", route)
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	udpServer.Shutdown()
	tcpServer.Shutdown()
}

func validHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return false
	}
	return true
}

func route(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 || !allowed(w, req) {
		dns.HandleFailed(w, req)
		return
	}
	for name, addr := range routes {
		if strings.HasSuffix(req.Question[0].Name, name) {
			proxy(addr, w, req)
			return
		}
	}
	var dnsServer = randomPublicServer()
	proxy(dnsServer, w, req)
}

func isTransfer(req *dns.Msg) bool {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeIXFR, dns.TypeAXFR:
			return true
		}
	}
	return false
}

func allowed(w dns.ResponseWriter, req *dns.Msg) bool {
	if !isTransfer(req) {
		return true
	}
	remote, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	for _, ip := range transferIPs {
		if ip == remote {
			return true
		}
	}
	return false
}

func proxy(addr string, w dns.ResponseWriter, req *dns.Msg) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	if isTransfer(req) {
		if transport != "tcp" {
			dns.HandleFailed(w, req)
			return
		}
		t := new(dns.Transfer)
		c, err := t.In(req, addr)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		if err = t.Out(w, req, c); err != nil {
			dns.HandleFailed(w, req)
			return
		}
		return
	}
	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}
