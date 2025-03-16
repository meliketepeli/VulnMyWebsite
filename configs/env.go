package configs

import (
	"github.com/joho/godotenv"
	"log"
	"os"
)

func EnvMongoURI() string {

	err := godotenv.Load() // yuklemeyi baslattim

	if err != nil {
		log.Fatal("Error loading .env file") // eger hata bos degilse
	}

	mongoURI := os.Getenv("MONGO_URI") //mongo baglantısını arama kısmı
	return mongoURI

}
