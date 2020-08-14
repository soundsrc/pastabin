package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/fcgi"
	"io/ioutil"
	"math/rand"
	"time"
	"strings"
	"html/template"
	"context"
	"strconv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo/options"
)

var basePath string = "/pastabin"

func main() {

	rand.Seed(time.Now().UnixNano())

	http.HandleFunc(basePath + "/", router)

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
			sendInternalServerError(w)
		}
	}()

	path := r.URL.Path

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	defer client.Disconnect(ctx)

	database := client.Database("pastabin")

	if !strings.HasPrefix(path, basePath) {
		w.WriteHeader(404)
		fmt.Fprintf(w, "Not found.")
		return
	}

	subPath := path[len(basePath):len(path)]

	if subPath == "/post" {
		postHandler(w, r, ctx, database)
	} else {
		defaultPageHandler(w, r, ctx, database)
	}
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

func sendInternalServerError(w http.ResponseWriter) {
	w.WriteHeader(500)
	fmt.Fprintf(w, "internal server error")
}

func readPageHandler(w http.ResponseWriter, r *http.Request, ctx context.Context, db *mongo.Database) {

	var err error = nil

	defer func() {
		if err != nil {
			sendInternalServerError(w)
		}
	}()

}


func defaultPageHandler(w http.ResponseWriter, r *http.Request, ctx context.Context, db *mongo.Database) {

	var err error = nil

	defer func() {
		if err != nil {
			sendInternalServerError(w)
		}
	}()
	
	tpl, err := ioutil.ReadFile("main.gohtml");
	if err != nil {
		return
	}

	t, err := template.New("main").Parse(string(tpl))
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
			w.WriteHeader(500)
			fmt.Fprintf(w, "internal server error")
		}
	}()

	err = r.ParseMultipartForm(4 * 1024 * 1024)
	if err != nil {
		return	
	}

	attachment := []byte{}
	
	filename := ""
	file, header, err := r.FormFile("file")
	if err == nil {
		defer file.Close()

		attachment = make([]byte, header.Size)
		bytesread, err := file.Read(attachment)
		if int64(bytesread) != header.Size || err != nil {
			return
		}
	}

	textInput := r.FormValue("text")
	expire, err := strconv.Atoi(r.FormValue("expire"))
	if err != nil {
		return
	}

	code := randSeq(6)
	postsCollection := db.Collection("posts")
	_, err = postsCollection.InsertOne(ctx, bson.M{
		"_id": code,
		"text": textInput,
		"filename": filename,
		"attachment": attachment,
		"attachmentInfo": header,
		"expireDate": time.Now().Add(time.Second * time.Duration(expire)),
	})
	if err != nil {
		return
	}

	http.Redirect(w, r, basePath + "/" + code, 302)
}

