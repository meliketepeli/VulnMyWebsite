package repository

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"myWebsite-main/models"
	"time"
)

type ProductRepositoryDB struct {
	ProductCollection *mongo.Collection
	// buradan ekleme silme guncelleme gibi islemleri yapacagız
}

type ProductRepository interface {
	Insert(product models.Product) (bool, error)
	//bool yerine string de olabilir

	// tum verileri almak için bir fonksiyon oluşturduk ve bu fonksiyon array olmalı
	GetAll() ([]models.Product, error)

	//delete oluşturuyoruz
	Delete(id primitive.ObjectID) (bool, error)
}

func (p *ProductRepositoryDB) Insert(product models.Product) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// düşün bir kanal acmışsın
	//10 saniye bağlanmayı dene demek
	defer cancel()
	// en son defer calısır

	product.Id = primitive.NewObjectID()
	// bunu farklı object id versin diye yazdık generate etsin

	result, err := p.ProductCollection.InsertOne(ctx, product)

	if err != nil || result.InsertedID == nil {
		errors.New("Failed to insert product")
		return false, err
	}
	log.Println("Başarıyla eklenen ürün:", product)
	return true, nil
}

func (p *ProductRepositoryDB) GetAll() ([]models.Product, error) {

	var product models.Product    // bir eleman
	var products []models.Product // birden fazla
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// baglantı actık
	defer cancel()

	result, err := p.ProductCollection.Find(ctx, bson.M{})
	// açtığım yolu verdim, result a aldıgım dokumanları verdim

	if err != nil {
		//log.Fatalln(err)
		log.Println("MongoDB'den veri alınırken hata oluştu:", err)
		return nil, err

	}

	// tek tek bu verdiğim dokumanları almam lazım!!!
	// tekrar baglantı yolunu actım
	for result.Next(ctx) {
		// eger documentta decode edebilecegim bir sey varsa decodela, product a ata
		if err := result.Decode(&product); err != nil {
			// log.Fatalln(err)
			log.Println("Belge decode edilirken hata oluştu:", err)
			return nil, err
		}
		// eger decode gerek yoksa ekle
		products = append(products, product)

	}
	// Döngü sonunda, eğer hata varsa onu döndürelim
	if err := result.Err(); err != nil {
		log.Println("Döngü sırasında hata oluştu:", err)
		return nil, err
	}

	log.Println("Başarıyla alınan ürünler:", products)
	return products, nil
}

func (p *ProductRepositoryDB) Delete(id primitive.ObjectID) (bool, error) {

	// once bir kanal oluşturuyoruz
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := p.ProductCollection.DeleteOne(ctx, bson.M{"id": id})

	if err != nil || result.DeletedCount <= 0 {
		return false, err
	}
	return true, nil
}

func NewProductRepositoryDB(dbClient *mongo.Collection) *ProductRepositoryDB {

	return &ProductRepositoryDB{dbClient}
}
