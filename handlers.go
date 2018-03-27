package webhooks

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/ilackarms/go-github-webhook-server/github"
)

const (
	headerEvent     = "X-GitHub-Event"  // HTTP header where the webhook event is stored
	headerSignature = "X-Hub-Signature" // HTTP header where the sha1 signature of the payload is stored
)

const (
	EventTypePing  = "ping"
	EventTypePush  = "push"
	EventTypeWatch = "watch"
)

type CallbackWatchEvent func(event *github.WatchEvent)
type CallbackPushEvent func(event *github.PushEvent)

// provides the http handler and interface for adding callbacks
type GithubWebhookHandler struct {
	out         io.Writer
	secretToken string

	// callbacks for various types of events
	callbacksForWatchEvent []CallbackWatchEvent
	callbacksForPushEvent  []CallbackPushEvent
}

func NewGithubWebhookHandler(secretToken string, out io.Writer) *GithubWebhookHandler {
	if out == nil {
		out = os.Stderr
	}
	return &GithubWebhookHandler{
		out:         out,
		secretToken: secretToken,
	}
}

// add a callback for Watch Events
func (h *GithubWebhookHandler) AddCallbackForWatchEvent(cb CallbackWatchEvent) {
	h.callbacksForWatchEvent = append(h.callbacksForWatchEvent, cb)
}

// add a callback for Push Events
func (h *GithubWebhookHandler) AddCallbackForPushEvent(cb CallbackPushEvent) {
	h.callbacksForPushEvent = append(h.callbacksForPushEvent, cb)
}

// The main HTTP Handler that handles github webhooks
func (h *GithubWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// read the HTTP request body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.err(w, r, err, http.StatusBadRequest)
		return
	}

	// validate signature
	if h.secretToken != "" {
		sign := r.Header.Get(headerSignature)

		// to compute the HMAC in order to check for equality with what has been sent by GitHub
		mac := hmac.New(sha1.New, []byte(h.secretToken))
		mac.Write(body)
		expectedHash := hex.EncodeToString(mac.Sum(nil))
		receivedHash := sign[5:] // remove 'sha1='

		// signature mismatch, do not process
		if !hmac.Equal([]byte(receivedHash), []byte(expectedHash)) {
			h.err(w, r, fmt.Sprintf("Mismatch between expected (%s) and received (%s) hash.", expectedHash, receivedHash), http.StatusBadRequest)
			return
		}
	}

	eventType := r.Header.Get(headerEvent)
	switch eventType {
	case EventTypePing:
		// return 200
		return
	case EventTypeWatch:
		var watch github.WatchEvent
		err := json.Unmarshal(body, &watch)
		if err != nil {
			h.err(w, r, err, http.StatusBadRequest)
			return
		}
		for _, cb := range h.callbacksForWatchEvent {
			cb(&watch)
		}
	case EventTypePush:
		var push github.PushEvent
		err := json.Unmarshal(body, &push)
		if err != nil {
			h.err(w, r, err, http.StatusBadRequest)
			return
		}
		for _, cb := range h.callbacksForPushEvent {
			cb(&push)
		}
	default:
		h.err(w, r, "support for "+eventType+" not yet implemented", http.StatusNotImplemented)
	}
}

func (h *GithubWebhookHandler) err(w http.ResponseWriter, r *http.Request, errOrString interface{}, status int) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	fmt.Fprintf(w, `{"message": "%v"}`, errOrString)
	fmt.Fprintf(h.out, "err: %v", errOrString)
}
