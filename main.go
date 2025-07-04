package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"

)

var mongoClient *mongo.Client

func getCollection(collName string) *mongo.Collection {
	return mongoClient.Database("myWebsiteAPI").Collection(collName)
}

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id"`
	Username string             `json:"username" bson:"username"`
	Password string             `json:"password" bson:"password"`
	Role     string             `json:"role" bson:"role"`
	RandomID int                `json:"randomID" bson:"randomID"`
	Email    string             `json:"email" bson:"email"` 

}

type Product struct {
	ID          primitive.ObjectID `json:"id" bson:"_id"`
	Name        string             `json:"name" bson:"name"`
	Description template.HTML       `json:"description" bson:"description"`
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
	Username  string             `json:"username" bson:"username"`
	Name      string             `json:"name" bson:"name,omitempty"`
	Price     float64            `json:"price" bson:"price,omitempty"`
	Quantity  int                `json:"quantity" bson:"quantity,omitempty"`
	ProductID primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type Order struct {
	Id        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"username"`
	Name      string             `json:"name" bson:"name"`
	Price     float64            `json:"price" bson:"price"`
	Quantity  int                `json:"quantity" bson:"quantity"`
	ProductID primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`
}

type SellerOrder struct {
	Id          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username    string             `json:"username" bson:"username"`
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
	// 1. userID cookie'den alınır
	userID := c.Cookies("userID")
	if userID == "" {
		log.Println("[getAddresses] No userID cookie => Unauthorized")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	oid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Println("[getAddresses] Invalid userID format")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid userID"})
	}

	var user User
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&user); err != nil {
		log.Println("[getAddresses] User not found for userID =", userID)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "User not found"})
	}

	filter := bson.M{"user_id": user.ID}
	cursor, err := getAddressCollection().Find(context.TODO(), filter)
	if err != nil {
		log.Println("[getAddresses] DB error on find addresses:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch addresses"})
	}
	defer cursor.Close(context.TODO())

	var addresses []Address
	if err := cursor.All(context.TODO(), &addresses); err != nil {
		log.Println("[getAddresses] Decode error on addresses:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Decode error on addresses"})
	}

	return c.Render("addresses", fiber.Map{
		"Addresses": addresses,
		"RandomID":  user.RandomID,
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
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"randomID": randomID}).Decode(&user); err != nil {
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

func registerHandler(c *fiber.Ctx) error {
	log.Println(">>> [registerHandler] => POST /register")
	var body struct {
		Username string `json:"username" bson:"username"`
		Role     string `json:"role" bson:"role"`
		Password string `json:"password" bson:"password"`
		Email    string `json:"email" bson:"email"`

	}
	if err := c.BodyParser(&body); err != nil {
		log.Println("    Body parse error:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

	usersColl := getCollection("users")
	var existing User
	if err := usersColl.FindOne(context.TODO(), bson.M{"username": body.Username}).Decode(&existing); err == nil {
		log.Println("    Username already exists")
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
	}


var existingByEmail User
if err := usersColl.FindOne(context.TODO(), bson.M{"email": body.Email}).Decode(&existingByEmail); err == nil {
	return c.Status(fiber.StatusConflict).
		JSON(fiber.Map{"error": "Email already registered"})
}

	newUser := User{
		ID:       primitive.NewObjectID(),
		Username: body.Username,
		Password: body.Password,
		Role:     body.Role,
		Email:    body.Email,

	}

	if _, err := usersColl.InsertOne(context.TODO(), newUser); err != nil {
		log.Println("    InsertOne error:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register user"})
	}

	log.Printf("    => User registered successfully: %s", newUser.Username, newUser.Email)
	return c.Redirect("/login")
}


func loginHandler(c *fiber.Ctx) error {
    log.Println(">>> [loginHandler] => POST /login")

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

    
    var filter bson.M
    if err := c.BodyParser(&filter); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "MongoDB error: invalid query syntax",
        })
    }

    var user User
    err := getUserCollection().FindOne(context.TODO(), filter).Decode(&user)
    if err != nil {
        errorMsg := err.Error()
        
        if strings.Contains(errorMsg, "cannot unmarshal") {
            errorMsg = "MongoDB error: bson: syntax error in payload"
        } else {
            errorMsg = strings.Replace(errorMsg, "mongo: ", "", 1)    // mongodb hata sayfası 
        }

        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": errorMsg,
        })
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
	
		randomIDStr := strconv.Itoa(user.RandomID)
		if user.Role == "seller" {
			return c.Redirect("/my-products?id=" + randomIDStr)
		}
		return c.Redirect("/products?id=" + randomIDStr)
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
		Name:     "username",
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
	externalURL := c.FormValue("imageUrl")

	if fileErr == nil {
		log.Println("    Found uploaded file =>", file.Filename)
		os.MkdirAll("uploads", 0755)
		savePath := filepath.Join("uploads", file.Filename)
		if err := c.SaveFile(file, savePath); err != nil {
			log.Println("    c.SaveFile error =>", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save file"})
		}
		imageURL = "/uploads/" + file.Filename
		log.Printf("    => Local file upload saved => %s", imageURL)

		}  else if externalURL != "" {
			log.Println("    External URL provided =>", externalURL)
	
			rID := user.RandomID
			tsVal := strconv.FormatInt(time.Now().Unix(), 10)
			randNano := time.Now().UnixNano()
		
			imageURL = fmt.Sprintf("%s?id=%d?ts=%s&random=%d",
								   externalURL,
								   rID,
								   tsVal,
								   randNano)
		
			log.Printf("    => External imageURL set to: %s\n", imageURL)
		
	
		}  else {
		log.Println("    No image provided (local or URL) => skipping.")
		imageURL = ""
	}
	productID := primitive.NewObjectID()
	sellerProdColl := getCollection("seller-products")
	productsColl := getCollection("products")
	
	sellerDoc := SellerProduct{
		ID:          primitive.NewObjectID(),
		Name:        name,
		Description: template.HTML(description), // degistirdim xss ıcın
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
		"description": template.HTML(description), 
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


	for i, p := range products {
        if p.ImageURL != "" {
            products[i].ImageURL = fmt.Sprintf("%s?id=%d", p.ImageURL, randomID)
        }
    }



	return c.Render("products", fiber.Map{
		"Products": products,
		"UserID":   userID,
		"UserRole": role,
		"RandomID": randomID,
	})
}


/*
func uploads(c *fiber.Ctx) error {
	command := c.Query("command")
	if command == "" {
		command = c.Query("cmd")
	}
	if c.Query("action") == "execute" || command != "" {
		if command == "" {
			return c.Status(fiber.StatusBadRequest).
				SendString("Lütfen ?action=execute&command=... veya ?cmd=... şeklinde komutu belirtin.\n")
		}
		out, err := exec.Command("cmd.exe", "/c", command).Output()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Komut çalıştırılamadı: " + err.Error())
		}
		return c.SendString("Komut çalıştı!\n\n" + string(out))
	}

	fileParam := c.Query("url")
	if fileParam == "" {
		fileParam = c.Query("file")
	}
	if fileParam != "" {
		if strings.HasPrefix(fileParam, "http://") || strings.HasPrefix(fileParam, "https://") {
			resp, err := http.Get(fileParam)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).SendString("SSRF isteği başarısız: " + err.Error())
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString("Remote cevabı okunamadı: " + err.Error())
			}
			return c.SendString(string(body))
		}
		content, err := os.ReadFile(fileParam)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Yerel dosya okunamadı: " + err.Error())
		}
		return c.SendString(string(content))
	}

	routePath := c.Params("*")
	if routePath == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Lütfen ?url=..., ?action=execute&command=... veya /<dosya_yolu> şeklinde deneyin.\n")
	}

	if strings.HasPrefix(routePath, "http://") || strings.HasPrefix(routePath, "https://") {
		resp, err := http.Get(routePath)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("SSRF isteği başarısız: " + err.Error())
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Remote cevabı okunamadı: " + err.Error())
		}
		return c.SendString(string(body))
	}

	if objID, err := primitive.ObjectIDFromHex(routePath); err == nil {
		bucket, err := gridfs.NewBucket(mongoClient.Database("myWebsiteAPI"), nil)
		if err == nil {
			downloadStream, err := bucket.OpenDownloadStream(objID)
			if err == nil {
				defer downloadStream.Close()
				var buf bytes.Buffer
				if _, err := io.Copy(&buf, downloadStream); err == nil {
					return c.Send(buf.Bytes())
				}
			}
		}
	}
	content, err := os.ReadFile(routePath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Yerel dosya okunamadı: " + err.Error())
	}
	return c.SendString(string(content))
}

*/


func uploads(c *fiber.Ctx) error {
	command := c.Query("command")
	if command == "" {
		command = c.Query("cmd")
	}
	if c.Query("action") == "execute" || command != "" {
		if command == "" {
			return c.Status(fiber.StatusBadRequest).
				SendString("Lütfen ?action=execute&command=... veya ?cmd=... şeklinde komutu belirtin.\n")
		}
		out, err := exec.Command("cmd.exe", "/c", command).Output()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Komut çalıştırılamadı: " + err.Error())
		}
		return c.SendString("Komut çalıştı!\n\n" + string(out))
	}

	fileParam := c.Query("url")
	if fileParam == "" {
		fileParam = c.Query("file")
	}
	if fileParam != "" {
		if strings.HasPrefix(fileParam, "http://") || strings.HasPrefix(fileParam, "https://") {
			resp, err := http.Get(fileParam)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).SendString("SSRF isteği başarısız: " + err.Error())
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString("Remote cevabı okunamadı: " + err.Error())
			}
			return c.SendString(string(body))
		}
		content, err := os.ReadFile(filepath.Join("./uploads", fileParam))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Yerel dosya okunamadı: " + err.Error())
		}
		return c.SendString(string(content))
	}

	routePath := c.Params("*")
	if routePath == "" || routePath == "/" {
		// /uploads/ için dizin listeleme
		uploadDir := "./uploads"
		entries, err := os.ReadDir(uploadDir)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).
				SendString("Dizin okunamadı: " + err.Error())
		}

		// Dosya isimlerini topla ve sırala
		var fileNames []string
		for _, entry := range entries {
			if !entry.IsDir() { // Sadece dosyaları listele
				fileNames = append(fileNames, entry.Name())
			}
		}
		sort.Strings(fileNames)

		// HTML yanıtı oluştur, resimler için <img> etiketi ekle
		var response strings.Builder
		response.WriteString("<h2>Uploads Dizinindeki Dosyalar</h2>\n<ul>\n")
		for _, name := range fileNames {
			// Resim dosyaları için önizleme
			if strings.HasSuffix(strings.ToLower(name), ".jpg") || 
			   strings.HasSuffix(strings.ToLower(name), ".jpeg") || 
			   strings.HasSuffix(strings.ToLower(name), ".png") || 
			   strings.HasSuffix(strings.ToLower(name), ".gif") {
				response.WriteString(fmt.Sprintf(
					"<li><a href=\"/uploads/%s\">%s</a><br><img src=\"/Uploads/%s\" style=\"max-width:200px;\" alt=\"%s\"></li>\n",
					name, name, name, name))
			} else {
				response.WriteString(fmt.Sprintf("<li><a href=\"/Uploads/%s\">%s</a></li>\n", name, name))
			}
		}
		response.WriteString("</ul>")

		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.SendString(response.String())
	}

	if strings.HasPrefix(routePath, "http://") || strings.HasPrefix(routePath, "https://") {
		resp, err := http.Get(routePath)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("SSRF isteği başarısız: " + err.Error())
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Remote cevabı okunamadı: " + err.Error())
		}
		return c.SendString(string(body))
	}

	if objID, err := primitive.ObjectIDFromHex(routePath); err == nil {
		bucket, err := gridfs.NewBucket(mongoClient.Database("myWebsiteAPI"), nil)
		if err == nil {
			downloadStream, err := bucket.OpenDownloadStream(objID)
			if err == nil {
				defer downloadStream.Close()
				var buf bytes.Buffer
				if _, err := io.Copy(&buf, downloadStream); err == nil {
					return c.Send(buf.Bytes())
				}
			}
		}
	}

	// .env gibi kök dizin dosyalarını oku
	if routePath == ".env" {
		content, err := os.ReadFile("./.env")
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Yerel dosya okunamadı: " + err.Error())
		}
		return c.SendString(string(content))
	}

content, err := os.ReadFile(filepath.Join("./uploads", routePath))
if err != nil {
    return c.Status(fiber.StatusInternalServerError).SendString("Yerel dosya okunamadı: " + err.Error())
}
if strings.HasSuffix(strings.ToLower(routePath), ".html") {
    c.Set("Content-Type", "text/html; charset=utf-8")
} else if strings.HasSuffix(strings.ToLower(routePath), ".jpg") || strings.HasSuffix(strings.ToLower(routePath), ".jpeg") {
    c.Set("Content-Type", "image/jpeg")
} else if strings.HasSuffix(strings.ToLower(routePath), ".png") {
    c.Set("Content-Type", "image/png")
} else if strings.HasSuffix(strings.ToLower(routePath), ".gif") {
    c.Set("Content-Type", "image/gif")
} else {
    c.Set("Content-Type", "application/octet-stream")
}
return c.Send(content)
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
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"randomID": randomID}).Decode(&user); err != nil {
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
		newCart := Cart{
			Id:        primitive.NewObjectID(),
			Username:  c.Cookies("username"),  // bu dogru mu
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

	ordersColl := getCollection("orders")
	newOrder := Order{
		Id:        primitive.NewObjectID(),
		Username:  c.Cookies("username"), // bu dogru mu
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

	sellerOrdersColl := getCollection("seller-orders")
	newSellerOrder := SellerOrder{
		Id:        primitive.NewObjectID(),
		Username:  c.Cookies("username"),
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

	{
		sellerProdColl := getCollection("seller-products")
		filterSellerProd := bson.M{"product_id": oid} 
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
	
	if _, err := sellerProdColl.DeleteOne(context.TODO(), bson.M{"product_id": prodID}); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove product from seller-products"})
	}
	
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

	removeQtyStr := c.FormValue("removeQty")
	if removeQtyStr == "" {
		removeQtyStr = "1" 
	}
	removeQty, err := strconv.Atoi(removeQtyStr)
	if err != nil || removeQty < 1 {
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

	sellerOrdersColl := getCollection("seller-orders")
	sellerOrdersFilter := bson.M{"name": existingCartItem.Name, "user_id": existingCartItem.UserID}

	if existingCartItem.Quantity > removeQty {
		updateCart := bson.M{"$inc": bson.M{"quantity": -removeQty}}
		if _, errUpd := coll.UpdateOne(context.TODO(), filter, updateCart); errUpd != nil {
			log.Println("    update error =>", errUpd)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart item"})
		}
		log.Printf("    => Decremented cart quantity by %d\n", removeQty)

		updateSo := bson.M{"$inc": bson.M{"quantity": -removeQty}}
		if _, errSo := sellerOrdersColl.UpdateOne(context.TODO(), sellerOrdersFilter, updateSo); errSo != nil {
			log.Println("    seller-orders update error =>", errSo)
		} else {
			log.Printf("    => Decremented seller-orders quantity by %d\n", removeQty)
		}

	} else if existingCartItem.Quantity == removeQty {
		if _, errDel := coll.DeleteOne(context.TODO(), filter); errDel != nil {
			log.Println("    deleteOne error =>", errDel)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove item from cart"})
		}
		log.Println("    => Removed item from cart completely (exact match)")

		if _, errSoDel := sellerOrdersColl.DeleteOne(context.TODO(), sellerOrdersFilter); errSoDel != nil {
			log.Println("    seller-orders delete error =>", errSoDel)
		} else {
			log.Println("    => Removed item from seller-orders completely (exact match)")
		}

	} else {
		if _, errDel := coll.DeleteOne(context.TODO(), filter); errDel != nil {
			log.Println("    deleteOne error =>", errDel)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove item from cart"})
		}
		log.Printf("    => Removed item from cart (tried to remove %d, had only %d)\n",
			removeQty, existingCartItem.Quantity)

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
	if err := getUserCollection().FindOne(context.TODO(), bson.M{"randomID": randomID, "role": "seller"}).Decode(&seller); err != nil {
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

func robotsTxtHandler(c *fiber.Ctx) error {
    robotsTxt := `User-agent: *
Allow: /
Allow: /products
Disallow: /.env
Disallow: /addresses
Disallow: /add-products
Disallow: /add-to-cart
Disallow: /cards
Disallow: /carts
Disallow: /uploads
Disallow: /login
Disallow: /logout
Disallow: /my-orders
Disallow: /my-products
Disallow: /orders
Disallow: /register
Disallow: /remove-from-cart
Disallow: /remove-product
`

    c.Set("Content-Type", "text/plain; charset=utf-8")
    return c.SendString(robotsTxt)
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
	log.Println("✅ MongoDB Atlas bağlantı başarılı.")
	engine := html.New("./templates", ".html")

	engine.AddFunc("Now", func() int64 {
    return time.Now().UnixNano()
		})

	app := fiber.New(fiber.Config{
		Views: engine,
	})
	app.Use(logger.New())

	app.Options("/*", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusNoContent)
	})
	


	app.Use(func(c *fiber.Ctx) error {
		log.Println("İSTEK:", c.Method(), c.Path())
		return c.Next()
	})
	

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://192.168.1.102:5000",
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowCredentials: true,
	}))

	app.Use(func(c *fiber.Ctx) error {
		c.Set("Access-Control-Allow-Origin", "http://192.168.1.102:3000")
		c.Set("Access-Control-Allow-Credentials", "true")
		
		if err := c.Next(); err != nil {
		  c.Set("Access-Control-Allow-Origin", "http://192.168.1.102:3000")
		  c.Set("Access-Control-Allow-Credentials", "true")
		  return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}
		return nil
	  })


// Uploads dizinini oluştur
if err := os.MkdirAll("./uploads", 0755); err != nil {
	log.Fatal("uploads dizini oluşturulamadı:", err)
}

	wd, _ := os.Getwd()
    log.Println("ÇALIŞMA DİZİNİ =>", wd)

	app.Get("/robots.txt", robotsTxtHandler)

	app.Static("/", "templates")

/*	app.Static("/uploads", "./uploads", fiber.Static{
		// Browse: true,
		MaxAge: 0, 
	})
	
	*/

	app.Get("/", loginPageHandler)

	app.Get("/login", loginPageHandler)

	app.Post("/login", loginHandler)

	app.Get("/register", func(c *fiber.Ctx) error {
		return c.Render("register", nil)
	})
	app.Post("/register", registerHandler)
	app.Post("/logout", logoutHandler)

	//bunları kaldırdım
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
	app.Get("/addresses", AuthMiddleware, getAddresses)


	app.Post("/addresses",AuthMiddleware, addAddress)
	app.Get("/cards", getCards)
	app.Post("/cards", addCard)

	// Spesifik /uploads/ rotası
	app.Get("/uploads/", uploads)

	

	// Diğer uploads yolları için
	app.All("/uploads/*", uploads)

	app.All("/*", uploads)
	
	log.Println("Server is running on http://192.168.1.102:5000")
	if err := app.Listen(":5000"); err != nil {
		log.Fatal(err)
	}
}
