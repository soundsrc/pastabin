package main

import (
	"bytes"
	"context"
	"errors"
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
	"regexp"
	"strconv"
	"strings"
	"time"
)

var basePath string = "/pastabin"

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
	Date             time.Time             `json:"date" bson:"date"`
}

func main() {

	rand.Seed(time.Now().UnixNano())

	http.HandleFunc(basePath+"/", router)

	l, err := net.Listen("tcp", "127.0.0.1:9000")
	if err != nil {
		panic(err)
	}

	fcgi.Serve(l, nil)

}

func router(w http.ResponseWriter, r *http.Request) {

	var err error = nil

	defer func() {
		if err != nil {
			sendInternalServerError(w, err)
		}
	}()

	path := r.URL.Path

	if !strings.HasPrefix(path, basePath) {
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
	var result VisitorRecord
	err = visitorsCollection.FindOne(ctx, bson.M{"remoteAddr": ipAddr}).Decode(&result)
	if err == nil {
		if result.Banned {
			w.WriteHeader(403)
			return
		}
	} else {
		err = nil
	}

	// if path contains stuff like .php or whatever, instaban
	if strings.Contains(path, ".php") {
		visitorRecord := VisitorRecord{
			ID: primitive.NewObjectID(),
			RemoteAddr: ipAddr,
			Banned: true,
			Date: time.Now(),
		};
		_, err = visitorsCollection.InsertOne(ctx, visitorRecord)
		if err != nil {
			return
		}
	}

	subPath := path[len(basePath):len(path)]

	if subPath == "/robots.txt" {
		robotsTxt := `
User-agent: *
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

		postHandler(w, r, ctx, database)
		return

	} 
	
	expr := regexp.MustCompile("/attachment/([A-Za-z0-9]{6})")
	matches := expr.FindAllStringSubmatch(subPath, -1)
	if (len(matches) > 0) {
		getAttachmentHandler(w, r, ctx, database, matches[0][1])
		return
	}

	expr = regexp.MustCompile("/([A-Za-z0-9]{6})")
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
	fmt.Fprintf(w, "Internal server error: %s", err)
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
		BasePath:    basePath,
		Text:        result.Text,
		InlineImage: false,
		InlineAudio: false,
		InlineVideo: false,
	}

	if result.AttachmentHeader != nil {

		data.Filename = result.AttachmentHeader.Filename
		data.AttachmentPath = template.URL(basePath + "/attachment/" + code)

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
		BasePath: basePath,
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

	http.Redirect(w, r, basePath+"/"+code, 302)
}
