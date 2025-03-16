package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"strconv"
	"time"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"sort"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
	"path/filepath"

)

var mongoClient *mongo.Client

func getCollection(collName string) *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection(collName)
}

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id"`
	Username string             `json:"username" bson:"Username"`
	Password string             `json:"password" bson:"Password"`
	Role     string             `json:"role" bson:"Role"`
	RandomID int                `json:"randomId" bson:"RandomID"`

}

type Product struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Quantity    int                `json:"quantity" bson:"quantity"`
	ImageURL    string             `json:"imageURL" bson:"imageURL"`
	SellerID    primitive.ObjectID `json:"sellerId" bson:"sellerId"`
}

type SellerProduct struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Quantity    int                `json:"quantity" bson:"quantity"`
	ImageURL    string             `json:"imageURL" bson:"imageURL"`
	ProductID   primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID      primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type Cart struct {
	Id        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"Username"`
	Name      string             `json:"name" bson:"name,omitempty"`
	Price     float64            `json:"price" bson:"price,omitempty"`
	Quantity  int                `json:"quantity" bson:"quantity,omitempty"`
	ProductID primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type Order struct {
	Id        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"Username"`
	Name      string             `json:"name" bson:"name"`
	Price     float64            `json:"price" bson:"price"`
	Quantity  int                `json:"quantity" bson:"quantity"`
	ProductID primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type SellerOrder struct {
	Id          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username    string             `json:"username" bson:"Username"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Quantity    int                `json:"quantity" bson:"quantity"`
	ProductID   primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID      primitive.ObjectID `json:"user_id" bson:"user_id"`
}

// Address -> Kullanıcının adresi
type Address struct {
	ID      primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID  primitive.ObjectID `json:"user_id" bson:"user_id"`
	Street  string             `json:"street" bson:"street"`
	City    string             `json:"city" bson:"city"`
	Country string             `json:"country" bson:"country"`
}

// Card -> Kullanıcının kart bilgisi
type Card struct {
	ID         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID     primitive.ObjectID `json:"user_id" bson:"user_id"`
	CardNumber string             `json:"card_number" bson:"card_number"`
	ExpiryDate string             `json:"expiry_date" bson:"expiry_date"`
	CVV        string             `json:"cvv" bson:"cvv"`
}

// Adres koleksiyonunu döndüren yardımcı fonksiyon
func getAddressCollection() *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection("addresses")
}

func getCartCollection() *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection("carts")
}

// Kart koleksiyonunu döndüren yardımcı fonksiyon
func getCardCollection() *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection("cards")
}

func getUserCollection() *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection("users")
}

func getAddresses(c *fiber.Ctx) error {
	// URL query parametresi "id" kontrolü (RandomID)
	qid := c.Query("id")
	if qid == "" {
		// Eğer query parametresi yoksa, cookie'den giriş yapan kullanıcıyı al ve RandomID'sini ekleyerek yönlendir.
		userID := c.Cookies("userID")
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		oid, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
		}
		var user User
		if err := getUserCollection().FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "User not found"})
		}
		// Yönlendirme: URL’ye RandomID ekleniyor.
		return c.Redirect(fmt.Sprintf("/addresses?id=%d", user.RandomID))
	}

	// URL'den gelen "id" değeri var, önce integer'a çevir.
	randomID, err := strconv.Atoi(qid)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}

	// RandomID değeri ile kullanıcıyı buluyoruz.
	var user User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID}).Decode(&user); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	// Bulunan kullanıcının _id'sine göre adresleri çekiyoruz.
	filter := bson.M{"user_id": user.ID}
	cursor, err := getAddressCollection().Find(context.TODO(), filter)
	if err != nil {
		log.Println("DB error on find addresses =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch addresses"})
	}
	defer cursor.Close(context.TODO())

	var addresses []Address
	if err := cursor.All(context.TODO(), &addresses); err != nil {
		log.Println("Decode error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error on addresses"})
	}

	return c.Render("addresses", fiber.Map{
		"Addresses": addresses,
		"RandomID":  randomID,
	})
}


func addAddress(c *fiber.Ctx) error {
    // Kullanıcının giriş yapmış olduğu userID cookie’si
    userID := c.Cookies("userID")
    if userID == "" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
    }

    uid, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
    }

    // Formdan gelen değerler (ör. street, city, country)
    street := c.FormValue("street")
    city := c.FormValue("city")
    country := c.FormValue("country")

    if street == "" || city == "" || country == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
    }

    newAddress := Address{
        ID:      primitive.NewObjectID(),
        UserID:  uid,
        Street:  street,
        City:    city,
        Country: country,
    }

    _, err = getAddressCollection().InsertOne(context.TODO(), newAddress)
    if err != nil {
        log.Println("Insert address error =>", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save address"})
    }

    // Ekleme başarılı olduğunda adresleri listeleme sayfasına yönlendirebilirsiniz
    return c.Redirect("/addresses")
}

func getCards(c *fiber.Ctx) error {
    // URL query parametresi "id" kontrolü (RandomID)
    qid := c.Query("id")
    if qid == "" {
        // Eğer query parametresi yoksa, cookie'den giriş yapan kullanıcıyı al ve RandomID'sini ekleyerek yönlendir.
        userID := c.Cookies("userID")
        if userID == "" {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
        }
        oid, err := primitive.ObjectIDFromHex(userID)
        if err != nil {
            return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
        }
        var user User
        if err := getUserCollection().FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "User not found"})
        }
        // Yönlendirme: URL’ye RandomID ekleniyor.
        return c.Redirect(fmt.Sprintf("/cards?id=%d", user.RandomID))
    }

    // URL'den gelen "id" değeri varsa, önce integer'a çevir.
    randomID, err := strconv.Atoi(qid)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
    }

    // RandomID değeri ile kullanıcıyı buluyoruz.
    var user User
    if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID}).Decode(&user); err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
    }

    // Bulunan kullanıcının _id'sine göre kart (cards) verilerini çekiyoruz.
    filter := bson.M{"user_id": user.ID}
    cursor, err := getCardCollection().Find(context.TODO(), filter)
    if err != nil {
        log.Println("DB error on find cards =>", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch cards"})
    }
    defer cursor.Close(context.TODO())

    var cards []Card
    if err := cursor.All(context.TODO(), &cards); err != nil {
        log.Println("Decode error =>", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error on cards"})
    }

    return c.Render("cards", fiber.Map{
        "Cards":    cards,
        "RandomID": randomID,
    })
}

func addCard(c *fiber.Ctx) error {
    userID := c.Cookies("userID")
    if userID == "" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
    }

    uid, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
    }

    cardNumber := c.FormValue("card_number")
    expiryDate := c.FormValue("expiry_date")
    cvv := c.FormValue("cvv")

    // Basit kontrol, gerçek uygulamada çok daha sıkı validasyon yapmalısınız
    if cardNumber == "" || expiryDate == "" || cvv == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
    }

    newCard := Card{
        ID:         primitive.NewObjectID(),
        UserID:     uid,
        CardNumber: cardNumber, 
        ExpiryDate: expiryDate,
        CVV:        cvv,
    }

    _, err = getCardCollection().InsertOne(context.TODO(), newCard)
    if err != nil {
        log.Println("Insert card error =>", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save card"})
    }

    return c.Redirect("/cards")
}



var jwtSecret = []byte("supersecretkey") 


func AuthMiddleware(c *fiber.Ctx) error {
	log.Println(">>> [AuthMiddleware] Checking userID cookie")
	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("    No userID cookie => Unauthorized")
		return c.Status(fiber.StatusUnauthorized).SendString("Unauthorized: no userID cookie")
	}
	log.Println("    userID cookie =", userID)
	return c.Next()
}

func JWTMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing token"})
		}
		tokenString = tokenString[7:]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
		}

		username, ok := claims["username"].(string)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username in token"})
		}

		c.Locals("username", username)
		return c.Next()
	}
}

func registerHandler(c *fiber.Ctx) error {
	log.Println(">>> [registerHandler] => POST /register")

	var body struct {
		Username string `json:"username" bson:"Username"`
		Role     string `json:"role" bson:"Role"`
		Password string `json:"password" bson:"Password"`
	}
	if err := c.BodyParser(&body); err != nil {
		log.Println("    Body parse error:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	usersColl := getCollection("users")
	var existing User
	if err := usersColl.FindOne(context.TODO(), bson.M{"Username": body.Username}).Decode(&existing); err == nil {
		log.Println("    Username already exists")
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
	}

	newUser := User{
		ID:       primitive.NewObjectID(),
		Username: body.Username,
		Password: body.Password, // Gerçek uygulamalarda şifreyi hashleyin!
		Role:     body.Role,
	}

	if _, err := usersColl.InsertOne(context.TODO(), newUser); err != nil {
		log.Println("    InsertOne error:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register user"})
	}

	log.Printf("    => User registered successfully: %s", newUser.Username)
	return c.Redirect("/login")
}


/*
func loginHandler(c *fiber.Ctx) error {
	log.Println(">>> [loginHandler] => POST /login")

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		log.Println("    Could not parse body:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	log.Printf("    username=%s password=%s", body.Username, body.Password)

	usersColl := getCollection("users")
	var user User
	if err := usersColl.FindOne(context.TODO(), bson.M{"Username": body.Username}).Decode(&user); err != nil {
		log.Println("    User not found:", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "There is no such user, please REGISTER"})
	}

	log.Printf("    FOUND => _id=%s, role=%s", user.ID.Hex(), user.Role)

	// Cookie set
	c.Cookie(&fiber.Cookie{
		Name:    "userID",
		Value:   user.ID.Hex(),
		Expires: time.Now().Add(24 * time.Hour),
	})
	c.Cookie(&fiber.Cookie{
		Name:    "Username",
		Value:   user.Username,
		Expires: time.Now().Add(24 * time.Hour),
	})

	log.Printf("    => Login success. userID cookie=%s (role=%s)", user.ID.Hex(), user.Role)
	if user.Role == "seller" {
		return c.JSON(fiber.Map{
			"role":        "seller",
			"redirectUrl": "/my-products",
			"message":     "Login successful (seller)",
		})
	}
	return c.JSON(fiber.Map{
		"role":        "user",
		"redirectUrl": "/products",
		"message":     "Login successful (user)",
	})
}
*/

/*
func loginHandler(c *fiber.Ctx) error {
	log.Println(">>> [loginHandler] => POST /login")

	var body map[string]interface{}

	if err := c.BodyParser(&body); err != nil {
		log.Println("    Could not parse body:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

log.Printf("    RAW INPUT => username=%v password=%v", body["username"], body["password"])
	usersColl := getCollection("users")
	var user User
	
	query := bson.M{
		"Username": body["username"],
		"Password": body["password"], 
	}

	log.Printf("username type: %T, value: %#v", body["username"], body["username"])
log.Printf("password type: %T, value: %#v", body["password"], body["password"])


	if err := usersColl.FindOne(context.TODO(), query).Decode(&user); err != nil {
		log.Println("    Login failed:", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	log.Printf("username type: %T, value: %#v", body["username"], body["username"])
log.Printf("password type: %T, value: %#v", body["password"], body["password"])


log.Printf("    => LOGIN SUCCESS (No password check)! user=%s", user.Username)
	
	c.Cookie(&fiber.Cookie{
		Name:    "userID",
		Value:   user.ID.Hex(),
		Expires: time.Now().Add(24 * time.Hour),
	})
	c.Cookie(&fiber.Cookie{
		Name:    "Username",
		Value:   user.Username,
		Expires: time.Now().Add(24 * time.Hour),
	})

	log.Printf("    => Login success. userID cookie=%s (role=%s)", user.ID.Hex(), user.Role)
	
	// 4) Kullanıcı rolüne göre yönlendirme
    // URL query param'larına ID ve username koyuyoruz
    redirectURL := ""
    if user.Role == "seller" {
        redirectURL = fmt.Sprintf("/my-products?id=%s&username=%s", user.ID.Hex(), user.Username)
    } else {
        redirectURL = fmt.Sprintf("/products?id=%s&username=%s", user.ID.Hex(), user.Username)
    }

    log.Printf("    => Redirecting to: %s", redirectURL)
    return c.Redirect(redirectURL)
	
}
*/

// loginHandler
func loginHandler(c *fiber.Ctx) error {
    log.Println(">>> [loginHandler] => POST /login")

    // 1) Body parse into a map
    var reqBody = make(map[string]interface{})
    if err := c.BodyParser(&reqBody); err != nil {
        log.Println("    Could not parse body:", err)
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
    }

    log.Printf("    RAW INPUT => username=%v password=%v", reqBody["username"], reqBody["password"])

    // Eski çerezleri temizle (opsiyonel)
    c.Cookie(&fiber.Cookie{
        Name:     "userID",
        Value:    "",
        Expires:  time.Now().Add(-1 * time.Hour),
    })
    c.Cookie(&fiber.Cookie{
        Name:     "Username",
        Value:    "",
        Expires:  time.Now().Add(-1 * time.Hour),
    })

    // 2) Sorgu
    query := bson.M{
        "Username": reqBody["username"],
        "Password": reqBody["password"],
    }
    log.Printf("MongoDB Query Attempt: %+v", query)

    // 3) DB
    usersColl := getUserCollection()

    var user User
    err := usersColl.FindOne(context.TODO(), query).Decode(&user)
    if err != nil {
        log.Printf("Login failed: %v", err)
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
    }

    log.Printf("Login successful: username=%s (role=%s)", user.Username, user.Role)

    // 4) Cookie set
    c.Cookie(&fiber.Cookie{
        Name:    "userID",
        Value:   user.ID.Hex(),
        Expires: time.Now().Add(24 * time.Hour),
    })
    c.Cookie(&fiber.Cookie{
        Name:    "Username",
        Value:   user.Username,
        Expires: time.Now().Add(24 * time.Hour),
    })

    // 5) Role redirect
    if user.Role == "seller" {
		return c.Redirect("/my-products?id=" + strconv.Itoa(user.RandomID))
	}
	
    return c.Redirect("/products?id=" + strconv.Itoa(user.RandomID))
}

// loginPageHandler => login.html 
func loginPageHandler(c *fiber.Ctx) error {
    return c.SendFile("templates/login.html") 
}
	

func logoutHandler(c *fiber.Ctx) error {
	log.Println(">>> [logoutHandler] => POST /logout")

	c.Cookie(&fiber.Cookie{
		Name:     "userID",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HTTPOnly: true,
	})
	c.Cookie(&fiber.Cookie{
		Name:     "Username",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		HTTPOnly: true,
	})
	log.Println("    Cookies cleared => redirect /")
	return c.Redirect("/")
}

/*
func addProduct(c *fiber.Ctx) error {
	log.Println(">>> [addProduct] => POST /add-products")

	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("    No userID => unauthorized")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	oid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Println("    Invalid userID hex:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID hex"})
	}
	var user User
	if err := getCollection("users").FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
		log.Println("    User not found:", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
	}
	log.Printf("    => User found: %s (role=%s)", user.Username, user.Role)

	if user.Role != "seller" {
		log.Println("    Permission denied (user not seller).")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Permission denied"})
	}


	var imageURL string
	file, fileErr := c.FormFile("image")
	if fileErr == nil {
		log.Println("    Found uploaded file =>", file.Filename)
		fileData, errOpen := file.Open()
		if errOpen != nil {
			log.Println("    file.Open error =>", errOpen)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to open file"})
		}
		defer fileData.Close()

		bucket, errBucket := gridfs.NewBucket(mongoClient.Database("myWebsiteAPI"))
		if errBucket != nil {
			log.Println("    gridfs.NewBucket error =>", errBucket)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Bucket error"})
		}

		uploadStream, errUpload := bucket.OpenUploadStream(file.Filename)
		if errUpload != nil {
			log.Println("    OpenUploadStream error =>", errUpload)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Upload stream error"})
		}
		defer uploadStream.Close()

		if _, errCopy := io.Copy(uploadStream, fileData); errCopy != nil {
			log.Println("    copying file data error =>", errCopy)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Copy file data error"})
		}
		imgID := uploadStream.FileID.(primitive.ObjectID)
		imageURL = "/file/" + imgID.Hex()
		log.Printf("    => Image stored in GridFS => %s", imageURL)
	} else {
		log.Println("    No image file found, skipping =>", fileErr)
		imageURL = ""
	}

	name := c.FormValue("name")
	description := c.FormValue("description")
	priceStr := c.FormValue("price")
	qtyStr := c.FormValue("quantity")

	if name == "" || description == "" || priceStr == "" || qtyStr == "" {
		log.Println("    Missing form fields => name, desc, price, quantity required.")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
	}

	priceVal, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		log.Println("    Invalid price =>", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid price"})
	}
	qtyVal, err := strconv.Atoi(qtyStr)
	if err != nil {
		log.Println("    Invalid quantity =>", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid quantity"})
	}

	productID := primitive.NewObjectID()
	sellerProdColl := getCollection("seller-products")
	productsColl := getCollection("products")

	sellerDoc := SellerProduct{
		ID:          primitive.NewObjectID(),
		Name:        name,
		Description: description,
		Price:       priceVal,
		Quantity:    qtyVal,
		ImageURL:    imageURL,
		ProductID:   productID,
		UserID:      user.ID,
	}

	if _, err := sellerProdColl.InsertOne(context.TODO(), sellerDoc); err != nil {
		log.Println("    InsertOne(seller-products) error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert seller-product"})
	}

	prodDoc := bson.M{
		"_id":         productID,
		"name":        name,
		"description": description,
		"price":       priceVal,
		"quantity":    qtyVal,
		"imageURL":    imageURL,
		"sellerId":    user.ID,
	}
	if _, err := productsColl.InsertOne(context.TODO(), prodDoc); err != nil {
		log.Println("    InsertOne(products) error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert product"})
	}

	log.Printf("    => SUCCESS: product '%s' inserted for user '%s'", productID.Hex(), user.Username)
	return c.Redirect("/my-products")
} 
	*/
	func addProduct(c *fiber.Ctx) error {
		log.Println(">>> [addProduct] => POST /add-products")
	
		// Cookie'den userID al
		userID := c.Cookies("userID")
		if userID == "" {
			log.Println("    No userID => unauthorized")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
	
		oid, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			log.Println("    Invalid userID hex:", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID hex"})
		}
	
		// DB'de user bul
		var user User
		if err := getCollection("users").FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
			log.Println("    User not found:", err)
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
		}
	
		// Role seller mı?
		if user.Role != "seller" {
			log.Println("    Permission denied (user not seller).")
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Permission denied"})
		}
	
		// Form field'lar
		name := c.FormValue("name")
		description := c.FormValue("description")
		priceStr := c.FormValue("price")
		qtyStr := c.FormValue("quantity")
	
		if name == "" || description == "" || priceStr == "" || qtyStr == "" {
			log.Println("    Missing required fields => name, desc, price, quantity required.")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
		}
	
		priceVal, err := strconv.ParseFloat(priceStr, 64)
		if err != nil {
			log.Println("    Invalid price =>", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid price"})
		}
		qtyVal, err := strconv.Atoi(qtyStr)
		if err != nil {
			log.Println("    Invalid quantity =>", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid quantity"})
		}
	
		// Dosya kaydetme
		var imageURL string
		file, fileErr := c.FormFile("image")
		if fileErr == nil {
			// => Dosya var
			log.Println("    Found uploaded file =>", file.Filename)
	
			// 1) Insecure: kaydı .exe veya .php uzantısı olsa bile engellemiyoruz
			os.MkdirAll("uploads", 0755) // uploads klasörünü oluştur (yoksa)
			savePath := filepath.Join("uploads", file.Filename)
	
			// Kaydet (dosya uzantısı / mime check YOK)
			if err := c.SaveFile(file, savePath); err != nil {
				log.Println("    c.SaveFile error =>", err)
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save file"})
			}
	
			// Artık .exe vb. dosya => /uploads/<filename> URL'sinden indirilebilir
			imageURL = "/uploads/" + file.Filename
			log.Printf("    => Insecure file upload saved => %s", imageURL)
		} else {
			// file yoksa normal (opsiyonel) => imageURL boş
			log.Println("    No image file found => skipping. err:", fileErr)
			imageURL = ""
		}
	
		// Mongo'ya kaydet
		productID := primitive.NewObjectID()
		sellerProdColl := getCollection("seller-products")
		productsColl := getCollection("products")
	
		sellerDoc := SellerProduct{
			ID:          primitive.NewObjectID(),
			Name:        name,
			Description: description,
			Price:       priceVal,
			Quantity:    qtyVal,
			ImageURL:    imageURL,
			ProductID:   productID,
			UserID:      user.ID, // Bu user'a ait
		}
	
		if _, err := sellerProdColl.InsertOne(context.TODO(), sellerDoc); err != nil {
			log.Println("    InsertOne(seller-products) error =>", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert seller-product"})
		}
	
		prodDoc := bson.M{
			"_id":         productID,
			"name":        name,
			"description": description,
			"price":       priceVal,
			"quantity":    qtyVal,
			"imageURL":    imageURL,
			"sellerId":    user.ID,
		}
		if _, err := productsColl.InsertOne(context.TODO(), prodDoc); err != nil {
			log.Println("    InsertOne(products) error =>", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert product"})
		}
	
		log.Printf("    => SUCCESS: product '%s' inserted for user '%s'", productID.Hex(), user.Username)
		return c.Redirect("/my-products")
	}
	
/*
func getMyProducts(c *fiber.Ctx) error {
	log.Println(">>> [getMyProducts] => GET /my-products")
	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("    No userID => unauthorized")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Println("    Invalid userID hex =>", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
	}

	filter := bson.M{"user_id": uid}
	cursor, err := getCollection("seller-products").Find(context.TODO(), filter)
	if err != nil {
		log.Println("    DB error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error"})
	}
	defer cursor.Close(context.TODO())

	var products []SellerProduct
	if err := cursor.All(context.TODO(), &products); err != nil {
		log.Println("    decode error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error"})
	}
	log.Printf("    => Found %d products for userID=%s", len(products), userID)

	return c.Render("my-products", fiber.Map{
		"SellerProducts": products,
	})
}
*/

func getMyProducts(c *fiber.Ctx) error {
	log.Println(">>> [getMyProducts] =>", c.Method(), c.OriginalURL())

	// Giriş yapan satıcının bilgilerini cookie'den alalım.
	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("No userID => unauthorized")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	oid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Println("Invalid userID hex:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
	}
	var seller User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&seller); err != nil {
		log.Println("Seller not found:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Seller not found"})
	}

	// Eğer URL query parametresi "id" yoksa, yönlendirme yapalım.
	qid := c.Query("id")
	if qid == "" {
		return c.Redirect(fmt.Sprintf("/my-products?id=%d", seller.RandomID))
	}
	// İsteğe gelen query parametresi, beklenen seller RandomID değeriyle uyumlu olmalı.
	if _, err := strconv.Atoi(qid); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}

	// Eğer POST isteği ise, güncelleme işlemini gerçekleştirelim.
	if c.Method() == fiber.MethodPost {
		productIDStr := c.FormValue("productID")
		newPriceStr := c.FormValue("newPrice")
		if productIDStr == "" || newPriceStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields for update"})
		}
		prodID, err := primitive.ObjectIDFromHex(productIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid productID"})
		}
		newPrice, err := strconv.ParseFloat(newPriceStr, 64)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid newPrice value"})
		}
		log.Printf("Update requested for productID %s, new unit price: %.2f", productIDStr, newPrice)

		// Filtre: sadece product_id koşuluna bakıyoruz.
		filter := bson.M{"product_id": prodID}
		log.Printf("Update filter: %+v", filter)

		// SellerProducts koleksiyonunda güncelleme yapalım.
		sellerProdColl := getCollection("seller-products")
		upRes, err := sellerProdColl.UpdateOne(context.TODO(), filter, bson.M{"$set": bson.M{"price": newPrice}})
		if err != nil {
			log.Println("SellerProducts update error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "SellerProducts update failed"})
		}
		log.Printf("SellerProducts update modified count: %d", upRes.ModifiedCount)

		// Aynı ürün varsa Products koleksiyonunda da güncelleyelim.
		productsColl := getCollection("products")
		upRes2, err := productsColl.UpdateOne(context.TODO(), bson.M{"_id": prodID}, bson.M{"$set": bson.M{"price": newPrice}})
		if err != nil {
			log.Println("Products update error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Products update failed"})
		}
		log.Printf("Products update modified count: %d", upRes2.ModifiedCount)

		return c.Redirect(c.OriginalURL())
	}

	// GET isteği için: Giriş yapan satıcının ürünlerini çekelim.
	sellerProdColl := getCollection("seller-products")
	filter := bson.M{"user_id": seller.ID}
	cursor, err := sellerProdColl.Find(context.TODO(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error: find seller-products"})
	}
	defer cursor.Close(context.TODO())

	var products []SellerProduct
	if err := cursor.All(context.TODO(), &products); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error"})
	}
	log.Printf("Found %d products for seller with RandomID %d", len(products), seller.RandomID)

	return c.Render("my-products", fiber.Map{
		"SellerProducts": products,
		"RandomID":       seller.RandomID,
	})
}

// getProducts: Benzer şekilde URL'de ?id parametresi yoksa, cookie'deki kullanıcı bilgilerine göre RandomID ekleyerek yönlendirir.
func getProducts(c *fiber.Ctx) error {
	qid := c.Query("id")
	if qid == "" {
		userID := c.Cookies("userID")
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		oid, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
		}
		var user User
		if err := getUserCollection().FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Redirect(fmt.Sprintf("/products?id=%d", user.RandomID))
	}

	randomID, err := strconv.Atoi(qid)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}

	userID := c.Cookies("userID")
	role := "guest"
	if userID != "" {
		oid, err := primitive.ObjectIDFromHex(userID)
		if err == nil {
			var user User
			if err := getUserCollection().FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err == nil {
				role = user.Role
			}
		}
	}

	cursor, err := getCollection("products").Find(context.TODO(), bson.M{})
	if err != nil {
		log.Println("DB error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch products"})
	}
	defer cursor.Close(context.TODO())

	var products []Product
	if err := cursor.All(context.TODO(), &products); err != nil {
		log.Println("decode error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode products"})
	}
	log.Printf("Found %d products total", len(products))

	return c.Render("products", fiber.Map{
		"Products": products,
		"UserID":   userID,
		"UserRole": role,
		"RandomID": randomID,
	})
}

func getFile(c *fiber.Ctx) error {
	log.Println(">>> [getFile] => GET /file/:id")
	fileIDHex := c.Params("id")
	fileID, err := primitive.ObjectIDFromHex(fileIDHex)
	if err != nil {
		log.Println("    Invalid fileID =>", fileIDHex)
		return c.Status(fiber.StatusBadRequest).SendString("Geçersiz dosya ID'si")
	}

	bucket, err := gridfs.NewBucket(mongoClient.Database("myWebsiteAPI"))
	if err != nil {
		log.Println("    Bucket error =>", err)
		return c.Status(fiber.StatusInternalServerError).SendString("GridFS bucket oluşturulamadı")
	}

	downloadStream, err := bucket.OpenDownloadStream(fileID)
	if err != nil {
		log.Println("    Dosya bulunamadı =>", err)
		return c.Status(fiber.StatusNotFound).SendString("Dosya bulunamadı")
	}
	defer downloadStream.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, downloadStream); err != nil {
		log.Println("    Dosya okunurken hata =>", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Dosya okunurken hata oluştu")
	}

	c.Type("jpeg")
	return c.Send(buf.Bytes())
}

func getCart(c *fiber.Ctx) error {
	// URL query parametresi "id" kontrolü (RandomID)
	qid := c.Query("id")
	if qid == "" {
		// Eğer query parametresi yoksa, cookie'den giriş yapan kullanıcıyı al ve RandomID'sini ekleyerek yönlendir.
		userID := c.Cookies("userID")
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		oid, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
		}
		var user User
		if err := getUserCollection().FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "User not found"})
		}
		// Yönlendirme: URL’ye RandomID ekleniyor.
		return c.Redirect(fmt.Sprintf("/carts?id=%d", user.RandomID))
	}

	// URL'den gelen "id" değeri varsa, önce integer'a çevir.
	randomID, err := strconv.Atoi(qid)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}

	// RandomID değeri ile kullanıcıyı buluyoruz.
	var user User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID}).Decode(&user); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	// Bulunan kullanıcının _id'sine göre cart (sepet) verilerini çekiyoruz.
	filter := bson.M{"user_id": user.ID}
	cursor, err := getCollection("carts").Find(context.TODO(), filter)
	if err != nil {
		log.Println("DB error on find carts =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch cart items"})
	}
	defer cursor.Close(context.TODO())

	var items []Cart
	if err := cursor.All(context.TODO(), &items); err != nil {
		log.Println("Decode error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error on cart items"})
	}

	return c.Render("cart", fiber.Map{
		"CartItems": items,
		"RandomID":  randomID,
	})
}


func getCartsFromDB(userID string) ([]Cart, error) {
	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid userID hex => %v", err)
	}
	filter := bson.M{"user_id": uid}
	cursor, err := getCollection("carts").Find(context.TODO(), filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find => %v", err)
	}
	defer cursor.Close(context.TODO())

	var carts []Cart
	if err := cursor.All(context.TODO(), &carts); err != nil {
		return nil, fmt.Errorf("decode error => %v", err)
	}
	return carts, nil
}

func addToCart(c *fiber.Ctx) error {
    log.Println(">>> [addToCart] => POST /add-to-cart")

    userID := c.Cookies("userID")
    if userID == "" {
        log.Println("    Unauthorized => no userID cookie")
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
    }

    productID := c.FormValue("product_id")
    name := c.FormValue("name")
    priceStr := c.FormValue("price")
    qtyStr := c.FormValue("quantity")

    oid, err := primitive.ObjectIDFromHex(productID)
    if err != nil {
        log.Println("    invalid product ID =>", err)
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
    }
    priceVal, err := strconv.ParseFloat(priceStr, 64)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid price"})
    }
    qtyVal, err := strconv.Atoi(qtyStr)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid quantity"})
    }

    uid, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid user ID"})
    }

    cartsColl := getCollection("carts")
    filter := bson.M{"product_id": oid, "user_id": uid}
    var existing Cart
    errFind := cartsColl.FindOne(context.TODO(), filter).Decode(&existing)
    if errFind == nil {
      
        update := bson.M{"$inc": bson.M{"quantity": qtyVal}}
        if _, errUpd := cartsColl.UpdateOne(context.TODO(), filter, update); errUpd != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart"})
        }
        log.Printf("    => Updated existing cart item, +%d quantity\n", qtyVal)
    } else {
    
        newCart := Cart{
            Id:        primitive.NewObjectID(),
            Username:  c.Cookies("Username"),
            UserID:    uid,                   
            Quantity:  qtyVal,
            Name:      name,
            Price:     priceVal,
            ProductID: oid,
        }
        _, errIns := cartsColl.InsertOne(context.TODO(), newCart)
        if errIns != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to insert cart item"})
        }
        log.Println("    => Inserted new cart item")
    }

    ordersColl := getCollection("orders")
    newOrder := Order{
        Id:        primitive.NewObjectID(),
        Username:  c.Cookies("Username"),  
        Name:      name,
        Price:     priceVal,
        Quantity:  qtyVal,
        ProductID: oid,
        UserID:    uid, 
    }
    _, errOrd := ordersColl.InsertOne(context.TODO(), newOrder)
    if errOrd != nil {
        log.Println("    InsertOne(orders) =>", errOrd)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add order"})
    }
    log.Println("    => Inserted new doc in 'orders'")

    sellerOrdersColl := getCollection("seller-orders")
    newSellerOrder := SellerOrder{
        Id:        primitive.NewObjectID(),
        Username:  c.Cookies("Username"), 
        Name:      name,
        Price:     priceVal,
        Quantity:  qtyVal,
        ProductID: oid,
        UserID:    uid, 
    }
    _, errSo := sellerOrdersColl.InsertOne(context.TODO(), newSellerOrder)
    if errSo != nil {
        log.Println("    InsertOne(seller-orders) =>", errSo)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add seller order"})
    }
    log.Println("    => Inserted new doc in 'seller-orders'")

    return c.Redirect("/carts")
}

func removeFromCart(c *fiber.Ctx) error {
	log.Println(">>> [removeFromCart] => POST /remove-from-cart")
	name := c.FormValue("name")
	if name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Product name is required"})
	}

	username := c.Query("username") 
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "username is required"})
	}

	coll := getCollection("carts")
	filter := bson.M{"name": name}
	var existingCartItem Cart
	if err := coll.FindOne(context.TODO(), filter).Decode(&existingCartItem); err != nil {
		log.Println("    item not found =>", err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Item not found in cart"})
	}

	if existingCartItem.Quantity > 1 {
		update := bson.M{"$inc": bson.M{"quantity": -1}}
		if _, err := coll.UpdateOne(context.TODO(), filter, update); err != nil {
			log.Println("    update error =>", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart item"})
		}
		log.Println("    => Decremented quantity by 1")
	} else {
		if _, err := coll.DeleteOne(context.TODO(), filter); err != nil {
			log.Println("    deleteOne error =>", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove item from cart"})
		}
		log.Println("    => Removed item from cart (quantity was 1)")
	}

	return c.Redirect(fmt.Sprintf("/carts?username=%s", username))
}

func getOrders(c *fiber.Ctx) error {
	log.Println(">>> [getOrders] => GET /orders")
	orders, err := getOrdersFromDB()
	if err != nil {
		log.Println("    DB error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch Orders"})
	}
	log.Printf("    => Found %d orders total", len(orders))

	return c.Render("order", fiber.Map{
		"Orders": orders,
	})
}

func getOrdersFromDB() ([]Order, error) {
	cursor, err := getCollection("orders").Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var orders []Order
	if err := cursor.All(context.TODO(), &orders); err != nil {
		return nil, err
	}
	return orders, nil
}


func getSellerOrders(c *fiber.Ctx) error {
	log.Println(">>> [getSellerOrders] => GET /my-orders")
	sellerorders, err := getSellerOrderFromDB()
	if err != nil {
		log.Println("    DB error =>", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch Seller Orders"})
	}
	log.Printf("    => Found %d seller-orders", len(sellerorders))

	return c.Render("seller-orders", fiber.Map{
		"SellerOrder": sellerorders,
	})
}

func getSellerOrderFromDB() ([]SellerOrder, error) {
	cursor, err := getCollection("seller-orders").Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var sorders []SellerOrder
	if err := cursor.All(context.TODO(), &sorders); err != nil {
		return nil, err
	}
	return sorders, nil
}

/*
func getMyOrders(c *fiber.Ctx) error {
    log.Println(">>> [getMyOrders] =>", c.Method(), c.OriginalURL())

    // URL path parametresi olarak gelen randomID'yi alıyoruz.
    paramID := c.Params("randomID")
    randomID, err := strconv.Atoi(paramID)
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
    }

    // "RandomID" alanına göre, satıcı rolündeki kullanıcıyı buluyoruz.
    var seller User
    if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID, "Role": "seller"}).Decode(&seller); err != nil {
        log.Println("Seller not found with randomID:", randomID, err)
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Seller not found"})
    }
    sellerID := seller.ID

    // POST isteği ise güncelleme işlemini yapalım.
    if c.Method() == fiber.MethodPost {
        productIdentifier := c.FormValue("productIdentifier")
        totalPriceStr := c.FormValue("totalPrice")
        if productIdentifier == "" || totalPriceStr == "" {
            return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields for update"})
        }
        newTotal, err := strconv.ParseFloat(totalPriceStr, 64)
        if err != nil {
            return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid totalPrice value"})
        }
        log.Printf("Update requested for product %s, new total: %.2f", productIdentifier, newTotal)
        // Burada ilgili güncelleme işlemini yapmanız gerekir.
        // Güncelleme tamamlandıktan sonra, güncel verilerle sayfayı yenilemek için aynı URL’ye yönlendiriyoruz.
        return c.Redirect(c.OriginalURL())
    }

    // GET isteği için devam ediyoruz...
    // Satıcıya ait seller-products'ı çekiyoruz.
    sellerProductsColl := getCollection("seller-products")
    filter := bson.M{"user_id": sellerID}
    cursor, err := sellerProductsColl.Find(context.TODO(), filter)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error: find seller-products"})
    }
    defer cursor.Close(context.TODO())

    productMap := make(map[primitive.ObjectID]string)
    for cursor.Next(context.TODO()) {
        var sp SellerProduct
        if err := cursor.Decode(&sp); err == nil {
            productMap[sp.ProductID] = sp.Name
        }
    }

    if len(productMap) == 0 {
        log.Println("=> No seller-products found for this seller => no orders")
        return c.Render("seller-orders", fiber.Map{
            "AggregatedProducts": []AggregatedProduct{},
            "RandomID":           seller.RandomID,
        })
    }

    // Satıcının siparişlerini çekiyoruz.
    sellerOrdersColl := getCollection("seller-orders")
    allCursor, err := sellerOrdersColl.Find(context.TODO(), bson.M{})
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error: find seller-orders"})
    }
    defer allCursor.Close(context.TODO())

    var allOrders []SellerOrder
    if err := allCursor.All(context.TODO(), &allOrders); err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error: seller-orders"})
    }

    // Siparişleri ürün bazında topluyoruz.
    aggregator := make(map[primitive.ObjectID]*AggregatedProduct)
    for _, order := range allOrders {
        prodName, ok := productMap[order.ProductID]
        if !ok {
            continue
        }
        if aggregator[order.ProductID] == nil {
            aggregator[order.ProductID] = &AggregatedProduct{
                ProductName: prodName,
                Buyers:      []BuyerInfo{},
            }
        }
        ag := aggregator[order.ProductID]
        ag.TotalQty += order.Quantity
        ag.TotalPrice += order.Price * float64(order.Quantity)
        var found bool
        for i, buyer := range ag.Buyers {
            if buyer.Username == order.Username {
                ag.Buyers[i].Quantity += order.Quantity
                ag.Buyers[i].TotalPrice += order.Price * float64(order.Quantity)
                found = true
                break
            }
        }
        if !found {
            ag.Buyers = append(ag.Buyers, BuyerInfo{
                Username:   order.Username,
                Quantity:   order.Quantity,
                TotalPrice: order.Price * float64(order.Quantity),
            })
        }
    }

    var result []AggregatedProduct
    for _, v := range aggregator {
        result = append(result, *v)
    }
    sort.Slice(result, func(i, j int) bool {
        return result[i].ProductName < result[j].ProductName
    })

    return c.Render("seller-orders", fiber.Map{
        "AggregatedProducts": result,
        "RandomID":           seller.RandomID,
    })
}
	*/

	func debugAllUsersHandler(c *fiber.Ctx) error {
		// .env dosyasını oku
		envData, err := os.ReadFile(".env")
		if err != nil {
			log.Println("Error reading .env file:", err)
			envData = []byte("Error reading .env file")
		}
	
		// MongoDB'deki users koleksiyonundan tüm kullanıcıları getir
		coll := getUserCollection()
		cursor, err := coll.Find(context.TODO(), bson.M{}) // Tüm kullanıcılar
		if err != nil {
			log.Println("DB find error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB find error"})
		}
		defer cursor.Close(context.TODO())
	
		var users []User
		if err := cursor.All(context.TODO(), &users); err != nil {
			log.Println("DB decode error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB decode error"})
		}
	
		log.Printf("=> Found %d users total", len(users))
		// .env dosyasının içeriğini ve kullanıcı listesini JSON olarak döndür
		return c.JSON(fiber.Map{
			"env":   string(envData),
			"users": users,
		})
	}
	
	
// Global tip tanımlamaları
type BuyerInfo struct {
	Username   string  `json:"username" bson:"username"`
	Quantity   int     `json:"quantity" bson:"quantity"`
	TotalPrice float64 `json:"totalPrice" bson:"totalPrice"`
}

type AggregatedProduct struct {
	ProductID   primitive.ObjectID `json:"productId" bson:"productId"`
	ProductName string             `json:"productName" bson:"productName"`
	TotalQty    int                `json:"totalQty" bson:"totalQty"`
	TotalPrice  float64            `json:"totalPrice" bson:"totalPrice"` // Bu artık unit price olarak kullanılacak
	Buyers      []BuyerInfo        `json:"buyers" bson:"buyers"`
}

func getMyOrders(c *fiber.Ctx) error {
	log.Println(">>> [getMyOrders] =>", c.Method(), c.OriginalURL())

	// Query parametresi "id" (randomID) kontrolü
	qid := c.Query("id")
	if qid == "" {
		userID := c.Cookies("userID")
		if userID == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		oid, err := primitive.ObjectIDFromHex(userID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
		}
		var user User
		if err := getUserCollection().FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Redirect(fmt.Sprintf("/my-orders?id=%d", user.RandomID))
	}

	randomID, err := strconv.Atoi(qid)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}

	// Satıcıyı, RandomID ve Role="seller" ile bulalım.
	var seller User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID, "Role": "seller"}).Decode(&seller); err != nil {
		log.Println("Seller not found with randomID:", randomID, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Seller not found"})
	}
	sellerID := seller.ID

	// POST isteğinde güncelleme işlemi
	if c.Method() == fiber.MethodPost {
		productIDStr := c.FormValue("productID")
		totalPriceStr := c.FormValue("totalPrice")
		if productIDStr == "" || totalPriceStr == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields for update"})
		}
		prodID, err := primitive.ObjectIDFromHex(productIDStr)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid productID"})
		}
		newTotal, err := strconv.ParseFloat(totalPriceStr, 64)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid totalPrice value"})
		}
		log.Printf("Update requested for productID %s, new unit price: %.2f", productIDStr, newTotal)

		// Filtreden "user_id" koşulunu kaldırıyoruz ki farklı sellerlar da güncelleme yapabilsin.
		filter := bson.M{"product_id": prodID}
		log.Printf("Update filter: %+v", filter)

		sellerProductsColl := getCollection("seller-products")
		upRes, err := sellerProductsColl.UpdateOne(
			context.TODO(),
			filter,
			bson.M{"$set": bson.M{"price": newTotal}},
		)
		if err != nil {
			log.Println("SellerProduct update error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "SellerProduct update failed"})
		}
		log.Printf("SellerProduct update modified count: %d", upRes.ModifiedCount)

		sellerOrdersColl := getCollection("seller-orders")
		upResOrders, err := sellerOrdersColl.UpdateMany(
			context.TODO(),
			filter,
			bson.M{"$set": bson.M{"price": newTotal}},
		)
		if err != nil {
			log.Println("SellerOrders update error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "SellerOrders update failed"})
		}
		log.Printf("SellerOrders update modified count: %d", upResOrders.ModifiedCount)

		return c.Redirect(c.OriginalURL())
	}

	// GET isteği için: Satıcının ürünlerini çekelim.
	sellerProductsColl := getCollection("seller-products")
	filter := bson.M{"user_id": sellerID}
	cursor, err := sellerProductsColl.Find(context.TODO(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error: find seller-products"})
	}
	defer cursor.Close(context.TODO())

	// Ürün bilgilerini saklamak için map oluşturuyoruz.
	type ProdInfo struct {
		Name  string
		Price float64
	}
	prodInfoMap := make(map[primitive.ObjectID]ProdInfo)
	for cursor.Next(context.TODO()) {
		var sp SellerProduct
		if err := cursor.Decode(&sp); err == nil {
			prodInfoMap[sp.ProductID] = ProdInfo{
				Name:  sp.Name,
				Price: sp.Price,
			}
		}
	}
	if len(prodInfoMap) == 0 {
		log.Println("=> No seller-products found for this seller => no orders")
		return c.Render("seller-orders", fiber.Map{
			"AggregatedProducts": []AggregatedProduct{},
			"RandomID":           seller.RandomID,
		})
	}

	// SellerOrders koleksiyonundan siparişleri alalım.
	sellerOrdersColl := getCollection("seller-orders")
	allCursor, err := sellerOrdersColl.Find(context.TODO(), bson.M{})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error: find seller-orders"})
	}
	defer allCursor.Close(context.TODO())

	var allOrders []SellerOrder
	if err := allCursor.All(context.TODO(), &allOrders); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error: seller-orders"})
	}

	// Aggregator: Burada artık toplam fiyatı, ürünün güncellenmiş unit price'sı olarak alıyoruz.
	aggregator := make(map[primitive.ObjectID]*AggregatedProduct)
	for _, order := range allOrders {
		pi, ok := prodInfoMap[order.ProductID]
		if !ok {
			continue
		}
		if aggregator[order.ProductID] == nil {
			aggregator[order.ProductID] = &AggregatedProduct{
				ProductID:   order.ProductID,
				ProductName: pi.Name,
				TotalQty:    order.Quantity,         // Toplam sipariş adedi
				TotalPrice:  pi.Price,               // Unit price olarak alınıyor, çarpma yapılmıyor
				Buyers: []BuyerInfo{
					{
						Username:   order.Username,
						Quantity:   order.Quantity,
						TotalPrice: pi.Price, // Unit price
					},
				},
			}
		} else {
			ag := aggregator[order.ProductID]
			ag.TotalQty += order.Quantity
			// Her sipariş için unit price aynıdır, o yüzden toplam fiyatı güncellemek yerine doğrudan unit price kullanıyoruz.
			// Eğer farklı siparişlerde farklı miktarlar varsa, isterseniz listeleyebilirsiniz.
			found := false
			for i, buyer := range ag.Buyers {
				if buyer.Username == order.Username {
					ag.Buyers[i].Quantity += order.Quantity
					// Unit price aynıdır, değişmeyecektir.
					found = true
					break
				}
			}
			if !found {
				ag.Buyers = append(ag.Buyers, BuyerInfo{
					Username:   order.Username,
					Quantity:   order.Quantity,
					TotalPrice: pi.Price,
				})
			}
		}
	}
	var result []AggregatedProduct
	for _, v := range aggregator {
		result = append(result, *v)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ProductName < result[j].ProductName
	})

	return c.Render("seller-orders", fiber.Map{
		"AggregatedProducts": result,
		"RandomID":           seller.RandomID,
	})
}


func main() {

	mongoURI := "mongodb+srv://me123:12345*@cluster0.76ktg.mongodb.net/myWebsiteAPI?retryWrites=true&w=majority"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(mongoURI)
	var err error
	mongoClient, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("MongoDB bağlantı hatası:", err)
	}
	if err := mongoClient.Ping(ctx, nil); err != nil {
		log.Fatal("MongoDB ping hatası:", err)
	}
	log.Println("✅ MongoDB Atlas bağlantısı başarılı.")

	engine := html.New("./templates", ".html") 
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://192.168.1.7:5000",
		AllowCredentials: true,
		//AllowMethods:"GET, POST, PUT, DELETE, OPTIONS",
	}))

	 app.Get("/robots.txt", debugAllUsersHandler)

	app.Static("/", "templates")
	app.Static("/uploads", "./uploads")

	app.Get("/", loginPageHandler)

	app.Get("/login", loginPageHandler)

	app.Post("/login", loginHandler)

	app.Get("/register", func(c *fiber.Ctx) error {
		return c.Render("register", nil)
	})

	app.Post("/register", registerHandler)
	
	app.Post("/logout", logoutHandler)

	app.Use(AuthMiddleware)



	app.Post("/add-to-cart", AuthMiddleware, addToCart)
	app.Get("/carts", AuthMiddleware, getCart)

	app.Post("/remove-from-cart", removeFromCart)

	app.Get("/add-products", func(c *fiber.Ctx) error {
		return c.Render("add-products", nil)
	})
	app.Post("/add-products", addProduct)

	//app.Get("/my-products", getMyProducts)
	app.All("/my-products", getMyProducts)


	app.Get("/products", getProducts)

	app.Get("/orders", getOrders)

//	app.Get("/my-orders",getMyOrders)
//	app.Get("/my-orders/:randomID", getMyOrders)      // RandomID içeren route

app.All("/my-orders", getMyOrders)



	// GridFS ile dosya çekme
	app.Get("/file/:id", getFile)

	// Yeni sayfalar
app.Get("/addresses", getAddresses)  // Adresleri listele
app.Post("/addresses", addAddress)   // Adres ekle

app.Get("/cards", getCards)          // Kartları listele
app.Post("/cards", addCard)          // Kart ekle


	log.Println("Server is running on http://192.168.1.7:5000")
	if err := app.Listen(":5000"); err != nil {
		log.Fatal(err)
	}
}