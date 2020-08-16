package main

import (
	"./lib"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"html/template"
	"io"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	BasePath     string
	Debug        bool
	RateLimit    time.Duration
	BanDuration  time.Duration
}

type PostRecord struct {
	ID               primitive.ObjectID    `json:"ID" bson:"_id,omitempty"`
	Code             string                `json:"code" bson:"code"`
	Text             string                `json:"text" bson:"text,omitempty"`
	Attachment       []byte                `json:"attachment" bson:"attachment,omitempty"`
	AttachmentHeader *multipart.FileHeader `json:"attachmentHeader" bson:"attachmentHeader,omitempty"`
	ExpireDate       time.Time             `json:"expireDate" bson:"expireDate"`
}

type VisitorRecord struct {
	ID               primitive.ObjectID    `json:"ID" bson:"_id,omitempty"`
	RemoteAddr       string                `json:"remoteAddr" bson:"remoteAddr"`
	Banned           bool                  `json:"banned" bson:"banned"`
	LastAccessDate   time.Time             `json:"lastAccessDate" bson:"lastAccessDate"`
	ExpireDate       time.Time             `json:"expireDate" bson:"expireDate"`
}

var globalOptions Options

func main() {

	rand.Seed(time.Now().UnixNano())

	portFlag := flag.String("p", "127.0.0.1:9000", "Bind address/port or socket")
	socketFlag := flag.String("s", "", "Socket path (overrides port)")
	flag.StringVar(&globalOptions.BasePath, "b", "", "Base path")
	flag.BoolVar(&globalOptions.Debug, "d", false, "Verbose debugging")
	rateLimitSecFlag := flag.Int("r", 10, "Rate limit (second)")
	banDurationDaysFlag := flag.Int("x", 90, "Ban duration (days)")

	flag.Parse()

	globalOptions.RateLimit = time.Second * time.Duration(*rateLimitSecFlag)
	globalOptions.BanDuration = time.Hour * time.Duration(24 * *banDurationDaysFlag)

	http.HandleFunc(globalOptions.BasePath + "/", router)

	var listener net.Listener
	var err error
	if *socketFlag != "" {
		os.Remove(*socketFlag)
		if listener, err = net.Listen("unix", *socketFlag); err != nil {
			panic(err)
		}
		if err = os.Chmod(*socketFlag, 0660); err != nil {
			panic(err)
		}
	} else {
		if listener, err = net.Listen("tcp", *portFlag); err != nil {
			panic(err)
		}
	}
	defer listener.Close()

	if err = lib.Sandbox(*socketFlag); err != nil {
		 panic(err)
	}

	fcgi.Serve(listener, nil)

}

func router(w http.ResponseWriter, r *http.Request) {

	var err error = nil

	defer func() {
		if err != nil {
			sendInternalServerError(w, err)
		}
	}()

	path := r.URL.Path

	if !strings.HasPrefix(path, globalOptions.BasePath) {
		w.WriteHeader(404)
		fmt.Fprintf(w, "Not found.")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	defer client.Disconnect(ctx)

	database := client.Database("pastabin")

	remoteAddrPort := strings.Split(r.RemoteAddr, ":")
	if (len(remoteAddrPort) == 0) {
		err = errors.New("Unable to determine remote addr")
		return
	}
	ipAddr := strings.Join(remoteAddrPort[0:len(remoteAddrPort)-1], ":")

	visitorsCollection := database.Collection("visitors")
	visitorRecord := VisitorRecord{
		ID: primitive.NewObjectID(),
		Banned: false,
		RemoteAddr: ipAddr,
		LastAccessDate: time.Time{},
	}

	err = visitorsCollection.FindOne(ctx, bson.M{"remoteAddr": ipAddr}).Decode(&visitorRecord)
	if err == nil {
		if visitorRecord.Banned {
			w.WriteHeader(403)
			return
		}
	} else {
		err = nil
	}

	// if path contains stuff like .php or whatever, instaban
	if strings.Contains(path, ".php") {
		visitorRecord.Banned = true
		visitorRecord.LastAccessDate = time.Now()
		visitorRecord.ExpireDate = time.Now().Add(globalOptions.BanDuration)

		var upsert bool = true
		_, err = visitorsCollection.ReplaceOne(ctx, bson.M{"_id": visitorRecord.ID}, visitorRecord, &options.ReplaceOptions{ Upsert: &upsert })
		if err != nil {
			return
		}

		send403ServerError(w)
		return
	}

	subPath := path[len(globalOptions.BasePath):len(path)]

	if subPath == "/robots.txt" {
		robotsTxt := `User-agent: *
Disallow: /
Disallow: /form/posts.php`
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(robotsTxt))
		return
	}

	if subPath == "/" {

		defaultPageHandler(w, r, ctx, database)
		return

	} 
	
	if subPath == "/post" {

		// enforce rate limit
		elapsedSeconds := time.Now().Sub(visitorRecord.LastAccessDate)
		if elapsedSeconds < globalOptions.RateLimit {
			_ = r.ParseMultipartForm(4 * 1024 * 1024) // can we skip this bit?
			w.WriteHeader(403)
			fmt.Fprintf(w, "Rate limit exceeded. Please wait %d seconds.", int((globalOptions.RateLimit - elapsedSeconds).Seconds()))
			return
		}

		visitorRecord.LastAccessDate = time.Now()
		visitorRecord.ExpireDate = time.Now().Add(time.Hour * time.Duration(2)) // don't need to keep record around

		var upsert bool = true
		_, err = visitorsCollection.ReplaceOne(ctx, bson.M{"_id": visitorRecord.ID}, visitorRecord, &options.ReplaceOptions{ Upsert: &upsert })
		if err != nil {
			return
		}

		postHandler(w, r, ctx, database)
		return

	} 
	
	expr := regexp.MustCompile("/attachment/([A-Za-z0-9]{6})$")
	matches := expr.FindAllStringSubmatch(subPath, -1)
	if (len(matches) > 0) {
		getAttachmentHandler(w, r, ctx, database, matches[0][1])
		return
	}

	expr = regexp.MustCompile("/([A-Za-z0-9]{6})$")
	matches = expr.FindAllStringSubmatch(subPath, -1)
	if (len(matches) > 0) {
		readPageHandler(w, r, ctx, database, subPath[1:7])
		return
	}
	
	send404ServerError(w)
}

// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go/22892986#22892986
var letters = []rune("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func sendInternalServerError(w http.ResponseWriter, err error) {
	w.WriteHeader(500)
	if globalOptions.Debug {
		fmt.Fprintf(w, "Internal server error: %s", err)
	} else {
		fmt.Fprintf(w, "Internal server error")
	}
}

func send404ServerError(w http.ResponseWriter) {
	w.WriteHeader(404)
	fmt.Fprintf(w, "Page not found")
}

func send403ServerError(w http.ResponseWriter) {
	w.WriteHeader(404)
	fmt.Fprintf(w, "Access denied")
}

func getAttachmentHandler(w http.ResponseWriter, r *http.Request, ctx context.Context, db *mongo.Database, code string) {
	var err error = nil

	defer func() {
		if err != nil {
			sendInternalServerError(w, err)
		}
	}()

	postsCollection := db.Collection("posts")
	var result PostRecord
	err = postsCollection.FindOne(ctx, bson.M{"code": code}).Decode(&result)
	if err != nil {
		return
	}

	haveContentType := false
	contentTypes, ok := result.AttachmentHeader.Header["Content-Type"];
	if ok && len(contentTypes) < 1 {
		contentType := contentTypes[0]
		w.Header().Set("Context-Type", contentType)
		haveContentType = true
	}

	if !haveContentType {
		w.Header().Set("Context-Type", "application/octet-stream")
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"" + result.AttachmentHeader.Filename + "\"")

	w.Write(result.Attachment)
}

func readPageHandler(w http.ResponseWriter, r *http.Request, ctx context.Context, db *mongo.Database, code string) {

	var err error = nil

	defer func() {
		if err != nil {
			sendInternalServerError(w, err)
		}
	}()

	postsCollection := db.Collection("posts")
	var result PostRecord
	err = postsCollection.FindOne(ctx, bson.M{"code": code}).Decode(&result)
	if err != nil {
		err = nil
		send404ServerError(w)
		return
	}

	t, err := template.New("display.gohtml").ParseFiles(
		"display.gohtml",
		"header.gohtml",
		"footer.gohtml")
	if err != nil {
		return
	}

	data := struct {
		BasePath       string
		Text           string
		Filename       string
		InlineImage    bool
		InlineAudio    bool
		InlineVideo    bool
		AttachmentPath template.URL
	}{
		BasePath:    globalOptions.BasePath,
		Text:        result.Text,
		InlineImage: false,
		InlineAudio: false,
		InlineVideo: false,
	}

	if result.AttachmentHeader != nil {

		data.Filename = result.AttachmentHeader.Filename
		data.AttachmentPath = template.URL(globalOptions.BasePath + "/attachment/" + code)

		if contentTypes, ok := result.AttachmentHeader.Header["Content-Type"]; ok && len(contentTypes) >= 1 {
			contentType := contentTypes[0]
			switch contentType {
				case
					"image/png",
					"image/jpeg",
					"image/gif",
					"image/bmp",
					"image/tuff",
					"image/svg":
					data.InlineImage = true
				case 
					"audio/aac",
					"audio/midi",
					"audio/x-midi",
					"audio/mpeg",
					"audio/mp3",
					"audio/ogg",
					"audio/opus",
					"audio/wav":
					data.InlineAudio = true
				case
					"video/x-msvideo",
					"video/mpeg",
					"video/mp4",
					"video/quicktime",
					"video/webm",
					"video/wx-ms-wmv":
					data.InlineVideo = true
			}
		}
	}

	err = t.Execute(w, data)
	if err != nil {
		return
	}

}

func defaultPageHandler(w http.ResponseWriter, r *http.Request, ctx context.Context, db *mongo.Database) {

	var err error = nil

	defer func() {
		if err != nil {
			sendInternalServerError(w, err)
		}
	}()


	t, err := template.New("main.gohtml").ParseFiles(
		"main.gohtml",
		"header.gohtml",
		"footer.gohtml")
	if err != nil {
		return
	}

	data := struct {
		BasePath string
	}{
		BasePath: globalOptions.BasePath,
	}
	err = t.Execute(w, data)
	if err != nil {
		return
	}

}

func postHandler(w http.ResponseWriter, r *http.Request, ctx context.Context, db *mongo.Database) {

	var err error = nil

	defer func() {
		if err != nil {
			sendInternalServerError(w, err)
		}
	}()

	err = r.ParseMultipartForm(4 * 1024 * 1024)
	if err != nil {
		return
	}

	attachment := []byte{}

	file, header, err := r.FormFile("file")
	if err == nil {
		defer file.Close()

		buffer := &bytes.Buffer{}
		if _, err := io.Copy(buffer, file); err != nil {
			return
		}

		attachment = buffer.Bytes()
	}

	textInput := r.FormValue("text")
	expire, err := strconv.Atoi(r.FormValue("expire"))
	if err != nil {
		return
	}

	// enforce max expire time
	if expire > 86400 {
		return
	}

	code := randSeq(6)
	postsCollection := db.Collection("posts")

	data := PostRecord{
		ID:               primitive.NewObjectID(),
		Code:             code,
		Text:             textInput,
		Attachment:       attachment,
		AttachmentHeader: header,
		ExpireDate:       time.Now().Add(time.Second * time.Duration(expire)),
	}

	_, err = postsCollection.InsertOne(ctx, data)
	if err != nil {
		return
	}

	http.Redirect(w, r, globalOptions.BasePath+"/"+code, 302)
}
