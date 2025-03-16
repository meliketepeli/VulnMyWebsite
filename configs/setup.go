package configs

// mongodb baglanma

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"time"
)

func ConnectDB() *mongo.Client { // mongo nun client ını donecek

	client, err := mongo.NewClient(options.Client().ApplyURI(EnvMongoURI()))
	// mongoya baglanmak ıcın bir client oluşturduk ve bu client client options ın instance ı
	// cunku env.go içinde biz git mongo uri nı al demiştik

	if err != nil {
		log.Fatal(err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 20*time.Second)
	// 20 saniyede baglanmaya calışsın olmazsa direkt kill lemek için yazdık
	err = client.Connect(ctx) // bunu yapmak için client a bir connect acıcam

	// ping atalım sıkıntı var mı yok mu baglanabiliyor mu istek atalım ctx ile
	err = client.Ping(ctx, nil)

	if err != nil {
		log.Fatal(err)
	}

	return client
}

var DB *mongo.Client = ConnectDB()

// her yerden dbye erişebilmek için

// mongodbde oluşturdugum collection ı oluşturma
func GetCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	//clientta bir db oluşturdum
	return client.Database("myWebsiteAPI").Collection(collectionName)
}
