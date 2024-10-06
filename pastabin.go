package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"

	"pastabin/lib"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Options struct {
	BasePath    string
	Debug       bool
	RateLimit   time.Duration
	BanDuration time.Duration
}

type EncryptedPostRecord struct {
	Text             string                `json:"text" bson:"text,omitempty"`
	Attachment       []byte                `json:"attachment" bson:"attachment,omitempty"`
	AttachmentHeader *multipart.FileHeader `json:"attachmentHeader" bson:"attachmentHeader,omitempty"`
}

type PostRecord struct {
	ID         primitive.ObjectID `json:"ID" bson:"_id,omitempty"`
	Code       string             `json:"code" bson:"code"`
	EncID      uint32             `json:"encID" bson:"encID"`
	Data       []byte             `json:"data" bson:"data"`
	ExpireDate time.Time          `json:"expireDate" bson:"expireDate"`
}

type VisitorRecord struct {
	ID             primitive.ObjectID `json:"ID" bson:"_id,omitempty"`
	RemoteAddr     string             `json:"remoteAddr" bson:"remoteAddr"`
	Banned         bool               `json:"banned" bson:"banned"`
	LastAccessDate time.Time          `json:"lastAccessDate" bson:"lastAccessDate"`
	ExpireDate     time.Time          `json:"expireDate" bson:"expireDate"`
}

type CryptoKey struct {
	Key        []byte
	ExpireDate time.Time
}

var globalOptions Options
var globalEncKeyMap map[uint32]*CryptoKey = make(map[uint32]*CryptoKey)

func purgeExpiredEncryptionKeys() {

	// Remove expired keys
	for id, key := range globalEncKeyMap {
		if time.Now().After(key.ExpireDate) {

			// zero memory
			for i := 0; i < 32; i++ {
				key.Key[i] = 0
			}

			if globalOptions.Debug {
				fmt.Printf("Remove enc key: %d", id)
			}

			// remove from map
			delete(globalEncKeyMap, id)
		}
	}

}

func wipeEncryptionKeys() {

	for _, key := range globalEncKeyMap {
		// zero memory
		for i := 0; i < 32; i++ {
			key.Key[i] = 0
		}
	}
	globalEncKeyMap = make(map[uint32]*CryptoKey)

}

func findOrGenerateEncryptionKey(validityDate time.Time) (uint32, *CryptoKey, error) {

	// check for valid keys, which must have an expiry date
	for id, key := range globalEncKeyMap {
		if validityDate.Before(key.ExpireDate) {
			return id, key, nil
		}
	}

	// generate new key
	idBytes := make([]byte, 4)
	if _, err := rand.Read(idBytes); err != nil {
		return 0, nil, err
	}

	id := binary.LittleEndian.Uint32(idBytes)
	key := &CryptoKey{}
	key.Key = make([]byte, 32)
	if _, err := rand.Read(key.Key); err != nil {
		return 0, nil, err
	}
	key.ExpireDate = validityDate.Add(time.Hour * time.Duration(1))

	if globalOptions.Debug {
		fmt.Printf("Add enc key: %d\n", id)
	}

	globalEncKeyMap[id] = key

	return id, key, nil
}

func encryptData(key, plainText []byte) ([]byte, error) {

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	return cipherText, nil

}

func decryptData(key, nonceAndCipherText []byte) ([]byte, error) {

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	nonce := nonceAndCipherText[0:gcm.NonceSize()]
	cipherText := nonceAndCipherText[gcm.NonceSize():]

	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil

}

func main() {

	portFlag := flag.String("p", "127.0.0.1:9000", "Bind address/port or socket")
	socketFlag := flag.String("s", "", "Socket path (overrides port)")
	flag.StringVar(&globalOptions.BasePath, "b", "", "Base path")
	flag.BoolVar(&globalOptions.Debug, "d", false, "Verbose debugging")
	rateLimitSecFlag := flag.Int("r", 10, "Rate limit (second)")
	banDurationDaysFlag := flag.Int("x", 90, "Ban duration (days)")

	flag.Parse()

	globalOptions.RateLimit = time.Second * time.Duration(*rateLimitSecFlag)
	globalOptions.BanDuration = time.Hour * time.Duration(24**banDurationDaysFlag)

	http.HandleFunc(globalOptions.BasePath+"/", router)

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

	ticker := time.NewTicker(time.Minute * time.Duration(30))
	go func() {
		for {
			<-ticker.C
			purgeExpiredEncryptionKeys()
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		for _ = range sigChan {
			if globalOptions.Debug {
				fmt.Printf("Caught SIGINT. Shutting down.\n")
			}
			wipeEncryptionKeys()
			os.Exit(0)
		}
	}()

	if err = fcgi.Serve(listener, nil); err != nil {
		panic(err)
	}

	if globalOptions.Debug {
		fmt.Printf("Shutting down.\n")
	}

	wipeEncryptionKeys()

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

	mongoHost, ok := os.LookupEnv("MONGO_HOST")
	if !ok {
		mongoHost = "localhost"
	}

	mongoPort := 27017
	mongoPortString, ok := os.LookupEnv("MONGO_PORT")
	if ok {
		mongoPort, err = strconv.Atoi(mongoPortString)
		if err != nil {
			return
		}
	}

	mongoUsername, ok := os.LookupEnv("MONGO_USERNAME")
	if !ok {
		mongoUsername = ""
	}

	mongoPassword, ok := os.LookupEnv("MONGO_PASSWORD")
	if !ok {
		mongoPassword = ""
	}

	mongoUserPassword := ""
	if mongoUsername != "" {
		mongoUserPassword += mongoUsername
	}

	if mongoPassword != "" {
		mongoUserPassword += ":" + mongoPassword
	}

	if mongoUserPassword != "" {
		mongoUserPassword += "@"
	}

	mongoURI := fmt.Sprintf("mongodb://%s%s:%d/?authSource=pastabin", mongoUserPassword, mongoHost, mongoPort)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		return
	}

	defer client.Disconnect(ctx)

	database := client.Database("pastabin")

	remoteAddrPort := strings.Split(r.RemoteAddr, ":")
	if len(remoteAddrPort) == 0 {
		err = errors.New("unable to determine remote addr")
		return
	}
	ipAddr := strings.Join(remoteAddrPort[0:len(remoteAddrPort)-1], ":")

	visitorsCollection := database.Collection("visitors")
	visitorRecord := VisitorRecord{
		ID:             primitive.NewObjectID(),
		Banned:         false,
		RemoteAddr:     ipAddr,
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

	// if path contains stuff like .php or robots.txt, instaban
	if strings.Contains(path, ".php") ||
		strings.Contains(path, "robots.txt") {
		visitorRecord.Banned = true
		visitorRecord.LastAccessDate = time.Now()
		visitorRecord.ExpireDate = time.Now().Add(globalOptions.BanDuration)

		var upsert = true
		_, err = visitorsCollection.ReplaceOne(ctx, bson.M{"_id": visitorRecord.ID}, visitorRecord, &options.ReplaceOptions{Upsert: &upsert})
		if err != nil {
			return
		}

		send403ServerError(w)
		return
	}

	subPath := path[len(globalOptions.BasePath):]

	if subPath == "/" {

		defaultPageHandler(w, r, ctx, database)
		return

	}

	if subPath == "/post" {

		// enforce rate limit
		elapsedTime := time.Now().Sub(visitorRecord.LastAccessDate)
		if elapsedTime < globalOptions.RateLimit {
			_ = r.ParseMultipartForm(4 * 1024 * 1024) // can we skip this bit?
			w.WriteHeader(403)
			fmt.Fprintf(w, "Rate limit exceeded. Please wait %d seconds.", int((globalOptions.RateLimit - elapsedTime).Seconds()))
			return
		}

		visitorRecord.LastAccessDate = time.Now()
		visitorRecord.ExpireDate = time.Now().Add(time.Hour * time.Duration(2)) // don't need to keep record around

		var upsert = true
		_, err = visitorsCollection.ReplaceOne(ctx, bson.M{"_id": visitorRecord.ID}, visitorRecord, &options.ReplaceOptions{Upsert: &upsert})
		if err != nil {
			return
		}

		postHandler(w, r, ctx, database)
		return

	}

	expr := regexp.MustCompile("/attachment/([A-Za-z0-9]{6})$")
	matches := expr.FindAllStringSubmatch(subPath, -1)
	if len(matches) > 0 {
		getAttachmentHandler(w, r, ctx, database, matches[0][1])
		return
	}

	expr = regexp.MustCompile("/([A-Za-z0-9]{6})$")
	matches = expr.FindAllStringSubmatch(subPath, -1)
	if len(matches) > 0 {
		readPageHandler(w, r, ctx, database, subPath[1:7])
		return
	}

	send404ServerError(w)
}

// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go/22892986#22892986
var letters = []rune("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")

// from FenderQ
func randomNumber(max int) (int, error) {
	bi := big.NewInt(int64(max))
	rn, err := rand.Int(rand.Reader, bi)
	if err != nil {
		return 0, err
	}
	n := int(rn.Int64())
	return n, nil
}

func randSeq(n int) (string, error) {
	b := make([]rune, n)
	for i := range b {
		var rn, err = randomNumber(len(letters))
		if err != nil {
			return "", err
		}
		b[i] = letters[rn]
	}
	return string(b), nil
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
	w.WriteHeader(403)
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

	if time.Now().After(result.ExpireDate) {
		err = nil
		send404ServerError(w)
		return
	}

	key, hasKey := globalEncKeyMap[result.EncID]
	if !hasKey {
		err = nil
		send404ServerError(w)
		return
	}

	decryptedData, err := decryptData(key.Key, result.Data)
	if err != nil {
		return
	}

	var record EncryptedPostRecord
	if err = bson.Unmarshal(decryptedData, &record); err != nil {
		return
	}

	haveContentType := false
	contentTypes, ok := record.AttachmentHeader.Header["Content-Type"]
	if ok && len(contentTypes) < 1 {
		contentType := contentTypes[0]
		w.Header().Set("Context-Type", contentType)
		haveContentType = true
	}

	if !haveContentType {
		w.Header().Set("Context-Type", "application/octet-stream")
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+record.AttachmentHeader.Filename+"\"")

	w.Write(record.Attachment)
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

	if time.Now().After(result.ExpireDate) {
		err = nil
		send404ServerError(w)
		return
	}

	key, hasKey := globalEncKeyMap[result.EncID]
	if !hasKey {
		err = nil
		send404ServerError(w)
		return
	}

	decryptedData, err := decryptData(key.Key, result.Data)
	if err != nil {
		return
	}

	var record EncryptedPostRecord
	if err = bson.Unmarshal(decryptedData, &record); err != nil {
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
		Text:        record.Text,
		InlineImage: false,
		InlineAudio: false,
		InlineVideo: false,
	}

	if record.AttachmentHeader != nil {

		data.Filename = record.AttachmentHeader.Filename
		data.AttachmentPath = template.URL(globalOptions.BasePath + "/attachment/" + code)

		if contentTypes, ok := record.AttachmentHeader.Header["Content-Type"]; ok && len(contentTypes) >= 1 {
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

	attachment := make([]byte, 0)

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

	if len(textInput) == 0 && len(attachment) == 0 {
		http.Redirect(w, r, globalOptions.BasePath+"/", 302)
		return
	}

	// enforce max expire time
	if expire > 86400 {
		err = errors.New("invalid expire time")
		return
	}

	code, err := randSeq(6)
	if err != nil {
		return
	}

	postsCollection := db.Collection("posts")

	record := EncryptedPostRecord{
		Text:             textInput,
		Attachment:       attachment,
		AttachmentHeader: header,
	}

	recordBytes, err := bson.Marshal(record)
	if err != nil {
		return
	}

	expireDate := time.Now().Add(time.Second * time.Duration(expire))
	encID, key, err := findOrGenerateEncryptionKey(expireDate)
	if err != nil {
		return
	}

	encryptedData, err := encryptData(key.Key, recordBytes)

	data := PostRecord{
		ID:         primitive.NewObjectID(),
		Code:       code,
		EncID:      encID,
		Data:       encryptedData,
		ExpireDate: expireDate,
	}

	_, err = postsCollection.InsertOne(ctx, data)
	if err != nil {
		return
	}

	http.Redirect(w, r, globalOptions.BasePath+"/"+code, 302)
}
