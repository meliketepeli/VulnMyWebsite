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
	"html/template"
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
	Description template.HTML             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Quantity    int                `json:"quantity" bson:"quantity"`
	ImageURL    string             `json:"imageURL" bson:"imageURL"`
	SellerID    primitive.ObjectID `json:"sellerId" bson:"sellerId"`
}

type SellerProduct struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Name        string             `json:"name" bson:"name"`
	Description template.HTML       `json:"description" bson:"description"`
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

type Address struct {
	ID      primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID  primitive.ObjectID `json:"user_id" bson:"user_id"`
	Street  string             `json:"street" bson:"street"`
	City    string             `json:"city" bson:"city"`
	Country string             `json:"country" bson:"country"`
}

type Card struct {
	ID         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID     primitive.ObjectID `json:"user_id" bson:"user_id"`
	CardNumber string             `json:"card_number" bson:"card_number"`
	ExpiryDate string             `json:"expiry_date" bson:"expiry_date"`
	CVV        string             `json:"cvv" bson:"cvv"`
}

func getAddressCollection() *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection("addresses")
}

func getCartCollection() *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection("carts")
}

func getCardCollection() *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection("cards")
}

func getUserCollection() *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection("users")
}

func getAddresses(c *fiber.Ctx) error {
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
		return c.Redirect(fmt.Sprintf("/addresses?id=%d", user.RandomID))
	}

	randomID, err := strconv.Atoi(qid)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}

	var user User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID}).Decode(&user); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

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
	userID := c.Cookies("userID")
	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
	}

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

	return c.Redirect("/addresses")
}

func getCards(c *fiber.Ctx) error {
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
		return c.Redirect(fmt.Sprintf("/cards?id=%d", user.RandomID))
	}

	randomID, err := strconv.Atoi(qid)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}

	var user User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID}).Decode(&user); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

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
		Password: body.Password,
		Role:     body.Role,
	}

	if _, err := usersColl.InsertOne(context.TODO(), newUser); err != nil {
		log.Println("    InsertOne error:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register user"})
	}

	log.Printf("    => User registered successfully: %s", newUser.Username)
	return c.Redirect("/login")
}

func loginHandler(c *fiber.Ctx) error {
	log.Println(">>> [loginHandler] => POST /login")
	var reqBody = make(map[string]interface{})
	if err := c.BodyParser(&reqBody); err != nil {
		log.Println("    Could not parse body:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}
	log.Printf("    RAW INPUT => username=%v password=%v", reqBody["username"], reqBody["password"])
	c.Cookie(&fiber.Cookie{
		Name:    "userID",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
	})
	c.Cookie(&fiber.Cookie{
		Name:    "Username",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
	})
	query := bson.M{
		"Username": reqBody["username"],
		"Password": reqBody["password"],
	}
	log.Printf("MongoDB Query Attempt: %+v", query)
	usersColl := getUserCollection()
	var user User
	err := usersColl.FindOne(context.TODO(), query).Decode(&user)
	if err != nil {
		log.Printf("Login failed: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}
	log.Printf("Login successful: username=%s (role=%s)", user.Username, user.Role)
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
	if user.Role == "seller" {
		return c.Redirect("/my-products?id=" + strconv.Itoa(user.RandomID))
	}
	return c.Redirect("/products?id=" + strconv.Itoa(user.RandomID))
}

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
	if user.Role != "seller" {
		log.Println("    Permission denied (user not seller).")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Permission denied"})
	}
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
	var imageURL string
	file, fileErr := c.FormFile("image")
	if fileErr == nil {
		log.Println("    Found uploaded file =>", file.Filename)
		os.MkdirAll("uploads", 0755)
		savePath := filepath.Join("uploads", file.Filename)
		if err := c.SaveFile(file, savePath); err != nil {
			log.Println("    c.SaveFile error =>", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save file"})
		}
		imageURL = "/uploads/" + file.Filename
		log.Printf("    => Insecure file upload saved => %s", imageURL)
	} else {
		log.Println("    No image file found => skipping. err:", fileErr)
		imageURL = ""
	}
	productID := primitive.NewObjectID()
	sellerProdColl := getCollection("seller-products")
	productsColl := getCollection("products")
	
	// Description değeri, template.HTML ile dönüştürülerek saklanır.
	sellerDoc := SellerProduct{
		ID:          primitive.NewObjectID(),
		Name:        name,
		Description: template.HTML(description), // Dönüştürme yapıldı
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
		"description": template.HTML(description), // Dönüştürme yapıldı
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


func getMyProducts(c *fiber.Ctx) error {
	log.Println(">>> [getMyProducts] =>", c.Method(), c.OriginalURL())
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
	qid := c.Query("id")
	if qid == "" {
		return c.Redirect(fmt.Sprintf("/my-products?id=%d", seller.RandomID))
	}
	if _, err := strconv.Atoi(qid); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}
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
		filter := bson.M{"product_id": prodID}
		log.Printf("Update filter: %+v", filter)
		sellerProdColl := getCollection("seller-products")
		upRes, err := sellerProdColl.UpdateOne(context.TODO(), filter, bson.M{"$set": bson.M{"price": newPrice}})
		if err != nil {
			log.Println("SellerProducts update error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "SellerProducts update failed"})
		}
		log.Printf("SellerProducts update modified count: %d", upRes.ModifiedCount)
		productsColl := getCollection("products")
		upRes2, err := productsColl.UpdateOne(context.TODO(), bson.M{"_id": prodID}, bson.M{"$set": bson.M{"price": newPrice}})
		if err != nil {
			log.Println("Products update error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Products update failed"})
		}
		log.Printf("Products update modified count: %d", upRes2.ModifiedCount)
		return c.Redirect(c.OriginalURL())
	}
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
/*
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
*/
func getFile(c *fiber.Ctx) error {
    log.Println(">>> [getFile] => GET /file/:id")

    fileIDHex := c.Params("id")
    // 1) Deneyelim: ObjectID parse
    objID, err := primitive.ObjectIDFromHex(fileIDHex)
    if err == nil {
        // Eğer parse BAŞARILI olduysa => GridFS'den oku
        bucket, _ := gridfs.NewBucket(mongoClient.Database("myWebsiteAPI"))
        downloadStream, err := bucket.OpenDownloadStream(objID)
        if err != nil {
            return c.Status(fiber.StatusNotFound).SendString("Dosya bulunamadı (GridFS)")
        }
        defer downloadStream.Close()

        var buf bytes.Buffer
        if _, err := io.Copy(&buf, downloadStream); err != nil {
            return c.Status(fiber.StatusInternalServerError).SendString("Dosya kopyalanamadı")
        }
        return c.Send(buf.Bytes())
    }
    localPath := fileIDHex // Kullanıcıdan gelen "id" değeri
    content, err2 := os.ReadFile(localPath)
    if err2 != nil {
        return c.Status(fiber.StatusInternalServerError).SendString("Yerel dosya okunamadı: " + err2.Error())
    }
    return c.SendString(string(content))
}


func getCart(c *fiber.Ctx) error {
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
		return c.Redirect(fmt.Sprintf("/carts?id=%d", user.RandomID))
	}
	randomID, err := strconv.Atoi(qid)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid randomID value"})
	}
	var user User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID}).Decode(&user); err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
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

/*
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

*/
func addToCart(c *fiber.Ctx) error {
	log.Println(">>> [addToCart] => POST /add-to-cart")

	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("    Unauthorized => no userID cookie")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	productID := c.FormValue("product_id")
	name := c.FormValue("name")
	priceStr := c.FormValue("price") // İstemcinin gönderdiği fiyat
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

	// 1) "carts" tablosunu güncelle veya yeni ekle
	cartsColl := getCollection("carts")
	filter := bson.M{"product_id": oid, "user_id": uid}
	var existing Cart

	errFind := cartsColl.FindOne(context.TODO(), filter).Decode(&existing)
	if errFind == nil {
		// ÜRÜN ZATEN VAR => quantity'yi artır + price client'tan gelen (iş mantığı açığı)
		update := bson.M{
			"$inc": bson.M{"quantity": qtyVal},
			"$set": bson.M{"price": priceVal},
		}

		if _, errUpd := cartsColl.UpdateOne(context.TODO(), filter, update); errUpd != nil {
			return c.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"error": "Failed to update cart"})
		}
		log.Printf("    => Updated existing cart item => quantity +%d, price => %.2f\n", qtyVal, priceVal)
	} else {
		// YENİ CART ITEM => Price/doğrudan client'tan
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
			return c.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"error": "Failed to insert cart item"})
		}
		log.Println("    => Inserted new cart item")
	}

	// 2) "orders" tablosuna da (her seferinde) insert
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
		return c.Status(fiber.StatusInternalServerError).
			JSON(fiber.Map{"error": "Failed to add order"})
	}
	log.Println("    => Inserted new doc in 'orders'")

	// 3) "seller-orders" tablosuna da insert
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
		return c.Status(fiber.StatusInternalServerError).
			JSON(fiber.Map{"error": "Failed to add seller order"})
	}
	log.Println("    => Inserted new doc in 'seller-orders'")

	// 4) [YENİ]: "products" tablosunu da update => satıcının "my-products" sayfası buradan okuyorsa
	{
		productsColl := getCollection("products")
		prodFilter := bson.M{"_id": oid} // Ürünün ID'si
		updateProducts := bson.M{"$set": bson.M{
			"price":    priceVal,
			"quantity": qtyVal,
		}}
		_, errProd := productsColl.UpdateOne(context.TODO(), prodFilter, updateProducts)
		if errProd != nil {
			log.Println("    UpdateOne(products) =>", errProd)
		} else {
			log.Printf("    => Updated 'products' => price=%.2f, quantity=%d\n", priceVal, qtyVal)
		}
	}

	// 5) [YENİ]: "seller-products" tablosuna da update => eğer satıcının "my-products" sayfası "seller-products" koleksiyonundan veri çekiyorsa
	{
		sellerProdColl := getCollection("seller-products")
		filterSellerProd := bson.M{"product_id": oid} // genelde product_id alanıyla eşleştirirsiniz
		updateSellerProd := bson.M{"$set": bson.M{
			"price":    priceVal,
			"quantity": qtyVal,
		}}
		_, errSp := sellerProdColl.UpdateOne(context.TODO(), filterSellerProd, updateSellerProd)
		if errSp != nil {
			log.Println("    UpdateOne(seller-products) =>", errSp)
		} else {
			log.Println("    => seller-products updated => price, quantity")
		}
	}

	return c.Redirect("/carts")
}

// Yeni removeProduct handler'ı:
func removeProduct(c *fiber.Ctx) error {
	productIDStr := c.FormValue("productID")
	if productIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing productID"})
	}
	prodID, err := primitive.ObjectIDFromHex(productIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid productID"})
	}
	sellerProdColl := getCollection("seller-products")
	productsColl := getCollection("products")
	
	// seller-products koleksiyonundan silme işlemi:
	if _, err := sellerProdColl.DeleteOne(context.TODO(), bson.M{"product_id": prodID}); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove product from seller-products"})
	}
	
	// products koleksiyonundan silme işlemi:
	if _, err := productsColl.DeleteOne(context.TODO(), bson.M{"_id": prodID}); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove product from products"})
	}
	return c.Redirect("/my-products")
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

	// [YENİ] => Kaç tane ürünü bir seferde sileceğimiz parametresi
	removeQtyStr := c.FormValue("removeQty")
	if removeQtyStr == "" {
		removeQtyStr = "1" // varsayılan 1
	}
	removeQty, err := strconv.Atoi(removeQtyStr)
	if err != nil || removeQty < 1 {
		// Hatalı veya <1 gelirse 1 sayalım
		removeQty = 1
	}

	coll := getCollection("carts")
	filter := bson.M{"name": name}

	var existingCartItem Cart
	if err := coll.FindOne(context.TODO(), filter).Decode(&existingCartItem); err != nil {
		log.Println("    item not found =>", err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Item not found in cart"})
	}

	log.Printf("    => We will remove %d of '%s' from cart\n", removeQty, existingCartItem.Name)

	// [YENİ] => seller-orders koleksiyonuna da aynı işlemi uygulayacağız
	sellerOrdersColl := getCollection("seller-orders")
	sellerOrdersFilter := bson.M{"name": existingCartItem.Name, "user_id": existingCartItem.UserID}

	if existingCartItem.Quantity > removeQty {
		// 1) Cart tablosunda quantity - removeQty
		updateCart := bson.M{"$inc": bson.M{"quantity": -removeQty}}
		if _, errUpd := coll.UpdateOne(context.TODO(), filter, updateCart); errUpd != nil {
			log.Println("    update error =>", errUpd)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart item"})
		}
		log.Printf("    => Decremented cart quantity by %d\n", removeQty)

		// 2) seller-orders tablosunda da quantity - removeQty
		updateSo := bson.M{"$inc": bson.M{"quantity": -removeQty}}
		if _, errSo := sellerOrdersColl.UpdateOne(context.TODO(), sellerOrdersFilter, updateSo); errSo != nil {
			log.Println("    seller-orders update error =>", errSo)
			// Normal akışı bozmamak için hata dönmüyoruz
		} else {
			log.Printf("    => Decremented seller-orders quantity by %d\n", removeQty)
		}

	} else if existingCartItem.Quantity == removeQty {
		// Tamamen sıfırlanacak => cart’tan sil
		if _, errDel := coll.DeleteOne(context.TODO(), filter); errDel != nil {
			log.Println("    deleteOne error =>", errDel)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove item from cart"})
		}
		log.Println("    => Removed item from cart completely (exact match)")

		// seller-orders'tan da sil
		if _, errSoDel := sellerOrdersColl.DeleteOne(context.TODO(), sellerOrdersFilter); errSoDel != nil {
			log.Println("    seller-orders delete error =>", errSoDel)
		} else {
			log.Println("    => Removed item from seller-orders completely (exact match)")
		}

	} else {
		// Kullanıcı removeQty, cart’taki quantity’den büyükse => hepsini sil
		if _, errDel := coll.DeleteOne(context.TODO(), filter); errDel != nil {
			log.Println("    deleteOne error =>", errDel)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove item from cart"})
		}
		log.Printf("    => Removed item from cart (tried to remove %d, had only %d)\n",
			removeQty, existingCartItem.Quantity)

		// seller-orders'tan da sil
		if _, errSoDel := sellerOrdersColl.DeleteOne(context.TODO(), sellerOrdersFilter); errSoDel != nil {
			log.Println("    seller-orders delete error =>", errSoDel)
		} else {
			log.Println("    => Removed item from seller-orders (quantity < removeQty scenario)")
		}
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

func debugAllUsersHandler(c *fiber.Ctx) error {
	envData, err := os.ReadFile(".env")
	if err != nil {
		log.Println("Error reading .env file:", err)
		envData = []byte("Error reading .env file")
	}
	coll := getUserCollection()
	cursor, err := coll.Find(context.TODO(), bson.M{})
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
	return c.JSON(fiber.Map{
		"env":   string(envData),
		"users": users,
	})
}

type BuyerInfo struct {
	Username   string  `json:"username" bson:"username"`
	Quantity   int     `json:"quantity" bson:"quantity"`
	TotalPrice float64 `json:"totalPrice" bson:"totalPrice"`
}

type AggregatedProduct struct {
	ProductID   primitive.ObjectID `json:"productId" bson:"productId"`
	ProductName string             `json:"productName" bson:"productName"`
	TotalQty    int                `json:"totalQty" bson:"totalQty"`
	TotalPrice  float64            `json:"totalPrice" bson:"totalPrice"`
	Buyers      []BuyerInfo        `json:"buyers" bson:"buyers"`
}

func getMyOrders(c *fiber.Ctx) error {
	log.Println(">>> [getMyOrders] =>", c.Method(), c.OriginalURL())
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
	var seller User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"RandomID": randomID, "Role": "seller"}).Decode(&seller); err != nil {
		log.Println("Seller not found with randomID:", randomID, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Seller not found"})
	}
	sellerID := seller.ID
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
	sellerProductsColl := getCollection("seller-products")
	filter := bson.M{"user_id": sellerID}
	cursor, err := sellerProductsColl.Find(context.TODO(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "DB error: find seller-products"})
	}
	defer cursor.Close(context.TODO())
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
				TotalQty:    order.Quantity,
				TotalPrice:  pi.Price,
				Buyers: []BuyerInfo{
					{
						Username:   order.Username,
						Quantity:   order.Quantity,
						TotalPrice: pi.Price,
					},
				},
			}
		} else {
			ag := aggregator[order.ProductID]
			ag.TotalQty += order.Quantity
			found := false
			for i, buyer := range ag.Buyers {
				if buyer.Username == order.Username {
					ag.Buyers[i].Quantity += order.Quantity
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
	}))

	wd, _ := os.Getwd()
    log.Println("ÇALIŞMA DİZİNİ =>", wd)

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

	app.Post("/remove-product", removeProduct)

	app.All("/my-products", getMyProducts)
	app.Get("/products", getProducts)
	app.Get("/orders", getOrders)
	app.All("/my-orders", getMyOrders)
	app.Get("/file/:id", getFile)
	app.Get("/addresses", getAddresses)
	app.Post("/addresses", addAddress)
	app.Get("/cards", getCards)
	app.Post("/cards", addCard)
	log.Println("Server is running on http://192.168.1.7:5000")
	if err := app.Listen(":5000"); err != nil {
		log.Fatal(err)
	}
}
