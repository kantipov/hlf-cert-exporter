package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	promNamespace = "hlf"
	labels        = []string{"cn", "o", "ou"}
	certNA        = prometheus.GaugeOpts{
		Name:      "cert_not_after",
		Namespace: promNamespace,
		Help:      "cert notAfter expressed as a Unix Epoch Time",
	}
	certNB = prometheus.GaugeOpts{
		Name:      "cert_not_before",
		Namespace: promNamespace,
		Help:      "cert notBefore expressed as a Unix Epoch Time",
	}
)

type parsedCert struct {
	cn string
	o  string
	ou string
	nb int64
	na int64
}

type exporter struct {
	k8s         *kubernetes.Clientset
	listOptions metav1.ListOptions
	namespaces  []string
}

func connectK8s() *kubernetes.Clientset {
	// create the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		// create the out-of-cluster config
		var kubeconfig *string
		if home := os.Getenv("HOME"); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}

		// use the current context in kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			panic(err.Error())
		}
	}

	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	return (clientset)
}

func parseSecret(raw []byte) (res parsedCert, err error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return res, errors.New("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return res, errors.New("failed to parse certificate")
	}

	res.cn = cert.Subject.CommonName
	if len(cert.Subject.OrganizationalUnit) > 0 {
		res.ou = strings.Join(cert.Subject.OrganizationalUnit, ",")
	}
	if len(cert.Subject.Organization) > 0 {
		res.o = strings.Join(cert.Subject.Organization, ",")
	}
	res.nb = cert.NotBefore.Unix()
	res.na = cert.NotAfter.Unix()
	return res, nil
}

func (e *exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc(
		prometheus.BuildFQName(certNA.Namespace, certNA.Subsystem, certNA.Name),
		certNA.Help,
		labels,
		nil,
	)
	ch <- prometheus.NewDesc(
		prometheus.BuildFQName(certNB.Namespace, certNB.Subsystem, certNB.Name),
		certNB.Help,
		labels,
		nil,
	)
}

func (e *exporter) Collect(ch chan<- prometheus.Metric) {
	gvNA := prometheus.NewGaugeVec(certNA, labels)
	gvNB := prometheus.NewGaugeVec(certNB, labels)
	e.scrape(gvNA, gvNB)
	gvNA.Collect(ch)
	gvNB.Collect(ch)
}

func (e *exporter) scrape(gvNA *prometheus.GaugeVec, gvNB *prometheus.GaugeVec) {
	for _, namespace := range e.namespaces {
		secretList, err := e.k8s.CoreV1().Secrets(namespace).List(e.listOptions)
		if err != nil {
			panic(err.Error())
		}
		for _, secret := range secretList.Items {
			for _, data := range secret.Data {
				cert, err := parseSecret(data)
				if err == nil {
					gvNA.WithLabelValues(cert.cn, cert.o, cert.ou).Set(float64(cert.na))
					gvNB.WithLabelValues(cert.cn, cert.o, cert.ou).Set(float64(cert.nb))
				}
			}
		}
	}
}

func main() {
	registerSignals()
	listen := flag.String("listen", ":9090", "The address to listen on for HTTP requests.")
	nsSelector := flag.String("ns", "", "List of namespaces to check, comma-separated")
	labelSelector := flag.String("label", "", "List of labels for filtering, comma-separated")
	flag.Parse()

	listOptions := metav1.ListOptions{
		LabelSelector: *labelSelector,
		Limit:         200,
	}

	k8s := connectK8s()
	namespaces := strings.Split(*nsSelector, ",")
	exporter := &exporter{k8s, listOptions, namespaces}
	prometheus.MustRegister(exporter)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>HLF cert exporter</title></head>
             <body>
             <h1>HLF cert exporter</h1>
             <p><a href='/metrics'>Metrics</a></p>
             </body>
             </html>`))
	})
	log.Println("Listening on", *listen)
	http.ListenAndServe(*listen, mux)
}

func registerSignals() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Print("Received SIGTERM, exiting...")
		os.Exit(0)
	}()
}
