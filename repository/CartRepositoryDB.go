package repository

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"nmyWebsite-main/models"
	"time"
)

type CartRepositoryDB struct {
	CartCollection *mongo.Collection
	// buradan ekleme silme guncelleme gibi islemleri yapacagız
}

type CartRepository interface {
	Insert(cart models.Cart) (bool, error)
	//bool yerine string de olabilir

	// tum verileri almak için bir fonksiyon oluşturduk ve bu fonksiyon array olmalı
	GetAll() ([]models.Cart, error)

	//delete oluşturuyoruz
	Delete(id primitive.ObjectID) (bool, error)
}

func (c *CartRepositoryDB) Insert(cart models.Cart) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// düşün bir kanal acmışsın
	//10 saniye bağlanmayı dene demek
	defer cancel()
	// en son defer calısır

	cart.Id = primitive.NewObjectID()
	// bunu farklı object id versin diye yazdık generate etsin

	result, err := c.CartCollection.InsertOne(ctx, cart)

	if err != nil || result.InsertedID == nil {
		errors.New("Failed to insert product")
		return false, err
	}
	log.Println("Başarıyla eklenen ürün:", cart)
	return true, nil
}

func (c *CartRepositoryDB) GetAll() ([]models.Cart, error) {

	var cart models.Cart
	var carts []models.Cart
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// baglantı actık
	defer cancel()

	result, err := c.CartCollection.Find(ctx, bson.M{})
	// açtığım yolu verdim, result a aldıgım dokumanları verdim

	if err != nil {
		//log.Fatalln(err)
		log.Println("MongoDB'den veri alınırken hata oluştu:", err)
		return nil, err

	}

	// tek tek bu verdiğim dokumanları almam lazım!!!
	// tekrar baglantı yolunu actım
	for result.Next(ctx) {
		// eger documentta decode edebilecegim bir sey varsa decodela, cart a ata
		if err := result.Decode(&cart); err != nil {
			// log.Fatalln(err)
			log.Println("Document decode edilirken hata oluştu:", err)
			return nil, err
		}
		// eger decode gerek yoksa ekle
		carts = append(carts, cart)

	}
	// Döngü sonunda, eğer hata varsa onu döndürelim
	if err := result.Err(); err != nil {
		log.Println("Döngü sırasında hata oluştu:", err)
		return nil, err
	}

	log.Println("Başarıyla alınan ürünler:", carts)
	return carts, nil
}

func (c *CartRepositoryDB) Delete(id primitive.ObjectID) (bool, error) {

	// once bir kanal oluşturuyoruz
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := c.CartCollection.DeleteOne(ctx, bson.M{"id": id})

	if err != nil || result.DeletedCount <= 0 {
		return false, err
	}
	return true, nil
}

func NewCartRepositoryDB(dbClient *mongo.Collection) *CartRepositoryDB {

	return &CartRepositoryDB{dbClient}
}
