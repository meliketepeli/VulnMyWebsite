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

type OrderRepositoryDB struct {
	OrderCollection *mongo.Collection
	// buradan ekleme silme guncelleme gibi islemleri yapacagız
}

type OrderRepository interface {
	Insert(order models.Order) (bool, error)
	//bool yerine string de olabilir

	// tum verileri almak için bir fonksiyon oluşturduk ve bu fonksiyon array olmalı
	GetAll() ([]models.Order, error)

	//delete oluşturuyoruz
	Delete(id primitive.ObjectID) (bool, error)
}

func (p *OrderRepositoryDB) Insert(order models.Order) (bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// düşün bir kanal acmışsın
	//10 saniye bağlanmayı dene demek
	defer cancel()
	// en son defer calısır

	order.Id = primitive.NewObjectID()
	// bunu farklı object id versin diye yazdık generate etsin

	result, err := p.OrderCollection.InsertOne(ctx, order)

	if err != nil || result.InsertedID == nil {
		errors.New("Failed to insert product")
		return false, err
	}
	log.Println("Başarıyla eklenen ürün:", order)
	return true, nil
}

func (p *OrderRepositoryDB) GetAll() ([]models.Order, error) {

	var order models.Order    // bir eleman
	var orders []models.Order // birden fazla
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// baglantı actık
	defer cancel()

	result, err := p.OrderCollection.Find(ctx, bson.M{})
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
		if err := result.Decode(&order); err != nil {
			// log.Fatalln(err)
			log.Println("Belge decode edilirken hata oluştu:", err)
			return nil, err
		}
		// eger decode gerek yoksa ekle
		orders = append(orders, order)

	}
	// Döngü sonunda, eğer hata varsa onu döndürelim
	if err := result.Err(); err != nil {
		log.Println("Döngü sırasında hata oluştu:", err)
		return nil, err
	}

	log.Println("Başarıyla alınan ürünler:", orders)
	return orders, nil
}

func (p *OrderRepositoryDB) Delete(id primitive.ObjectID) (bool, error) {

	// once bir kanal oluşturuyoruz
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := p.OrderCollection.DeleteOne(ctx, bson.M{"id": id})

	if err != nil || result.DeletedCount <= 0 {
		return false, err
	}
	return true, nil
}

func NewOrderRepositoryDB(dbClient *mongo.Collection) *OrderRepositoryDB {

	return &OrderRepositoryDB{dbClient}
}
