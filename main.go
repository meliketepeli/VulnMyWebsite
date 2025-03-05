package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"log"
	"newProject/configs"
	"strconv"
	"time"	
)

var client *mongo.Client

var jwtSecret = []byte("supersecretkey")

func registerPageHandler(c *fiber.Ctx) error {

	return c.SendFile("templates/register.html") // register.html dosyasını döndür

}
func registerHandler(c *fiber.Ctx) error {
	var user User

	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid input format")
	}

	collection := client.Database("myWebsiteAPI").Collection("users")
	
	var existingUser User
	err := collection.FindOne(context.TODO(), bson.M{"Username": user.Username}).Decode(&existingUser)

	if err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "This user already exists. Please log in!"})
	}

	// Eğer hata `mongo.ErrNoDocuments` değilse, başka bir hata var demektir.
	if err != mongo.ErrNoDocuments {
		return c.Status(fiber.StatusInternalServerError).SendString("Database error: " + err.Error())
	}

	// 🚨 Şifre **hashlenmeden** düz metin olarak kaydediliyor!
	_, err = collection.InsertOne(context.TODO(), bson.M{
		"Username": user.Username,
		"Role":     user.Role,
		"Password": user.Password, // Şifre düz metin olarak kaydedildi ❗
	})

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to register user: " + err.Error())
	}

	// Kullanıcı çerezini oluştur ve giriş sayfasına yönlendir
	c.Cookie(&fiber.Cookie{
		Name:     "Username",
		Value:    user.Username,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	return c.Redirect("/login")
}
func loginHandler(c *fiber.Ctx) error {
	var reqBody map[string]interface{}

	if err := c.BodyParser(&reqBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request format"})
	}

// **Eski çerezleri temizle**
c.Cookie(&fiber.Cookie{
	Name:     "userID",
	Value:    "",
	Expires:  time.Now().Add(-1 * time.Hour), // Anında sil
})

c.Cookie(&fiber.Cookie{
	Name:     "Username",
	Value:    "",
	Expires:  time.Now().Add(-1 * time.Hour), // Anında sil
})

// MongoDB case-sensitive olduğu için "Username" ve "Password" doğru olmalı
query := bson.M{
	"Username": reqBody["username"],
	"Password": reqBody["password"],
}

// MongoDB'ye gönderilecek sorguyu logla
log.Printf("MongoDB Query Attempt: %+v", query)

client := configs.DB
collection := configs.GetCollection(client, "users")


var user struct {
	ID       primitive.ObjectID `json:"id" bson:"_id"`
	Username string             `json:"username" bson:"Username"`
	Password string             `json:"password" bson:"Password"`
	Role     string             `json:"role" bson:"Role"`
}

// **NoSQL Injection açığını test etmek için direkt query kullanıyoruz**
err := collection.FindOne(context.TODO(), query).Decode(&user)


if err != nil {
	log.Printf("Login failed: %v", err)
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
}

	// ✅ Kullanıcıyı giriş yapmış olarak belirle (ÇEREZLERİ DÜZGÜN AYARLA)
	c.Cookie(&fiber.Cookie{
		Name:     "userID",
		Value:    user.ID.Hex(),
		Expires:  time.Now().Add(24 * time.Hour),
		// HTTPOnly: false, // False yaparak JS erişimine izin verdim
		
	})

	c.Cookie(&fiber.Cookie{
		Name:     "Username",
		Value:    user.Username,
		Expires:  time.Now().Add(24 * time.Hour),
		// HTTPOnly: false, // False yaparak JS erişimine izin vermiş oldum
		
	})

	log.Printf("Login successful: username=%s", user.Username)

	// Kullanıcının rolüne göre yönlendirme yap
	if user.Role == "user" {
		return c.Redirect("/products?id=" + user.ID.Hex())
	} else if user.Role == "seller" {
		return c.Redirect("/my-products?id=" + user.ID.Hex())
	}


	// Kullanıcıyı oturum açmış olarak işaretle (session veya token kullanabilirsiniz)
    c.Locals("userID", user.ID)  // Kullanıcı ID'sini oturumda saklıyoruz

	return c.JSON(fiber.Map{
		"role":    user.Role,
		"message": "Login successful",
	})
}

// 📌 **İlk olarak login.html göster**
func loginPageHandler(c *fiber.Ctx) error {
	return c.SendFile("templates/login.html")
}

func AuthMiddleware(c *fiber.Ctx) error {
	userID := c.Cookies("userID") 

	if userID == "" {
		log.Println("Unauthorized - No userID in cookie")
		return c.Redirect("/login")
	}
	/*

	// ✅ Kullanıcının kimliğini doğrulamak için MongoDB'yi kontrol et
	collection := client.Database("myWebsiteAPI").Collection("users")

	var user User
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Println("Unauthorized - Invalid userID format")
		return c.Redirect("/login")
	}

	err = collection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user)

	if err != nil {
		log.Println("Unauthorized - Invalid userID in cookie")
		return c.Redirect("/login")
	}
		*/
	

	c.Locals("userID", userID)
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


func logoutHandler(c *fiber.Ctx) error {

	c.Cookie(&fiber.Cookie{
		Name:     "userID",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		// HTTPOnly: true,  xss koruması saglıyor, ondan kaldırdım
	})

	c.Cookie(&fiber.Cookie{
		Name:     "Username",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		// HTTPOnly: true,
	})

	return c.Redirect("/")
}

type Cart struct {
	Id        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Username  string             `json:"username" bson:"Username"`
	Name      string             `json:"name" bson:"name,omitempty"`
	Price     float64            `json:"price" bson:"price,omitempty"` //32
	Quantity  int                `json:"quantity" bson:"quantity,omitempty"`
	ProductID primitive.ObjectID `json:"product_id" bson:"product_id"`
	UserID    primitive.ObjectID `json:"user_id" bson:"user_id"`

	// image url de olsa guzel olur ama image url sıkıntı biraz
}

func getCartsFromDB(userID string) ([]Cart, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID is required")
	}

	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid userID format")
	}

	client := configs.DB
	collection := configs.GetCollection(client, "carts")

	filter := bson.M{"user_id": uid}
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cart items: %v", err)
	}
	defer cursor.Close(context.TODO())

	var carts []Cart
	if err := cursor.All(context.TODO(), &carts); err != nil {
		return nil, fmt.Errorf("failed to decode cart items: %v", err)
	}

	return carts, nil
}

func getCart(c *fiber.Ctx) error {
	userID := c.Cookies("userID")
	log.Printf("user id from cookie: %v", userID)

	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	carts, err := getCartsFromDB(userID)
	if err != nil {
		log.Printf("Failed to fetch cart items: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch cart items"})
	}

	return c.Render("cart", fiber.Map{
		"CartItems": carts,
	})
}

func addToCart(c *fiber.Ctx) error {
    userID := c.Cookies("userID")
    log.Printf("User ID from cookie: %v", userID)

    if userID == "" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
    }

    uid, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        log.Printf("Invalid user ID from cookie: %s", userID)
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid User ID format!"})
    }

    // **FORM VERİLERİNİ AL VE KONTROL ET**
    productID := c.FormValue("product_id")
    log.Printf("✅ Extracted product_id: %s", productID)

    if productID == "" {
        log.Println("🚨 HATA: Formdan gelen 'product_id' boş!")
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Product ID is missing!"})
    }

    oid, err := primitive.ObjectIDFromHex(productID)
    if err != nil {
        log.Printf("Invalid product ID format: %s", productID)
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product ID"})
    }

    client := configs.DB
    cartCollection := configs.GetCollection(client, "carts")
    productCollection := configs.GetCollection(client, "products")
    ordersCollection := configs.GetCollection(client, "orders")
    sellerOrdersCollection := configs.GetCollection(client, "seller-orders")

    var product struct {
        Name     string  `json:"name" bson:"name"`
        Price    float64 `json:"price" bson:"price"`
        SellerID string  `json:"sellerId" bson:"sellerId"`
    }

    err = productCollection.FindOne(context.TODO(), bson.M{"_id": oid}).Decode(&product)
    if err != nil {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Product not found"})
    }

    filter := bson.M{"product_id": oid, "user_id": uid}
    update := bson.M{"$inc": bson.M{"quantity": 1}}

    result, err := cartCollection.UpdateOne(context.TODO(), filter, update)

    if err != nil {
        log.Println("🚨 Sepetteki ürün güncellenirken hata oluştu:", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart item"})
    }

    if result.MatchedCount == 0 {
        log.Println("⚠️ Ürün sepette bulunamadı, yeni olarak ekleniyor...")

        newCartItem := Cart{
            Id:        primitive.NewObjectID(),
            Username:  c.Cookies("Username"),
            UserID:    uid,
            Quantity:  1,
            Name:      product.Name,
            Price:     product.Price,
            ProductID: oid,
        }

        _, err = cartCollection.InsertOne(context.TODO(), newCartItem)
        if err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add item to cart"})
        }
    } else {
        log.Println("✅ Ürün sepette bulundu, miktar artırıldı.")
    }

    // **Orders Koleksiyonuna Ekle**
    order := Order{
        Id:        primitive.NewObjectID(),
        Username:  c.Cookies("Username"),
        Name:      product.Name,
        Price:     product.Price,
        Quantity:  1, 
        ProductID: oid,
        UserID:    uid,
    }

    _, err = ordersCollection.InsertOne(context.TODO(), order)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add order"})
    }

    // **Seller Orders Koleksiyonuna Ekle**
    sellerOrder := SellerOrder{
        Id:        primitive.NewObjectID(),
        Username:  c.Cookies("Username"),
        Name:      product.Name,
        Price:     product.Price,
        Quantity:  1,
        ProductID: oid,
        UserID:    uid,
    }

    _, err = sellerOrdersCollection.InsertOne(context.TODO(), sellerOrder)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add seller order"})
    }

    log.Println("✅ Ürün sepete başarıyla eklendi veya güncellendi! Kullanıcı yönlendiriliyor...")

    return c.Redirect("/carts?id=" + userID)
}


type Product struct {
	ID          string  `json:"id" bson:"_id"`
	Name        string  `json:"name" bson:"name"`
	Description string  `json:"description" bson:"description"`
	Price       float64 `json:"price" bson:"price"`
	Quantity    int     `json:"quantity" bson:"quantity"`
	ImageURL    string  `json:"imageURL" bson:"imageURL"`
	SellerID    string  `json:"sellerId" bson:"sellerId"`
	//seller  id ekledim.
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
	// bu aslında seller id ama user id yaptım.
}

func getSellerProductsFromDB(userID string) ([]SellerProduct, error) {


	if userID == "" {
		return nil, fmt.Errorf("userID is required")
	}

	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid userID format")
	}

	client := configs.DB
	collection := configs.GetCollection(client, "seller-products")

	filter := bson.M{"user_id": uid}
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch product items: %v", err)
	}
	defer cursor.Close(context.TODO())

	var products []SellerProduct
	if err := cursor.All(context.TODO(), &products); err != nil {
		return nil, fmt.Errorf("failed to decode seller-product items: %v", err)
	}
	return products, nil
}

func getMyProducts(c *fiber.Ctx) error {
	userID := c.Cookies("userID")
	log.Printf("user id from cookie: %v", userID)

	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	// Sellerın product çek
	sellerProducts, err := getSellerProductsFromDB(userID)
	if err != nil {
		log.Printf("Failed to fetch cart items: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch cart items"})
	}

	if err != nil {
		log.Printf("Failed to fetch product items: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch product items"})
	}

	return c.Render("my-products", fiber.Map{
		"SellerProducts": sellerProducts,
	})
}



func addProduct(c *fiber.Ctx) error {
	userID := c.Cookies("userID")
	log.Printf("User ID from cookie: %v", userID)

	if userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	uid, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		log.Printf("Invalid user ID format: %s", userID)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid User ID format!"})
	}

	client := configs.DB
	userCollection := configs.GetCollection(client, "users")

	var user struct {
		Role string `json:"role" bson:"Role"`
	}

	err = userCollection.FindOne(c.Context(), bson.M{"_id": uid}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
	}

	if user.Role != "seller" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Permission denied"})
	}

	productID := primitive.NewObjectID()

	// Dosya yükleme kısmı
	file, err := c.FormFile("image")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "No file uploaded"})
	}

	fileData, err := file.Open()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
	}
	defer fileData.Close()

	// GridFS'e dosya yükleme buna bak
	bucket, err := gridfs.NewBucket(client.Database("myWebsiteAPI"))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create GridFS bucket"})
	}

	uploadStream, err := bucket.OpenUploadStream(file.Filename)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to open upload stream"})
	}
	defer uploadStream.Close()

	if _, err := io.Copy(uploadStream, fileData); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to copy file data"})
	}

	imageID := uploadStream.FileID.(primitive.ObjectID)
	imageURL := fmt.Sprintf("/file/%s", imageID.Hex())


	log.Println("🚀 [DEBUG] addProduct fonksiyonu çağrıldı!")
	// Form verileri 
	name := c.FormValue("name")
	description := c.FormValue("description")
	priceStr := c.FormValue("price")
	quantityStr := c.FormValue("quantity")

	if name == "" || description == "" || priceStr == "" || quantityStr == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
    }

	log.Printf("📦 Ürün Ekleniyor: Name: %s, Description: %s, Price: %s, Quantity: %s", name, description, priceStr, quantityStr)


	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid price value"})
	}

	quantity, err := strconv.Atoi(quantityStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid quantity value"})
	}

	sellerProduct := SellerProduct{
		ID:          primitive.NewObjectID(),
		Name:        name,
		Description: description,
		Price:       price,
		Quantity:    quantity,
		ImageURL:    imageURL,
		UserID:      uid,
		ProductID:   productID, 
	}

	product := bson.M{
		"_id":         productID, 
		"name":        name,
		"description": description,
		"price":       price,
		"quantity":    quantity,
		"imageURL":    imageURL,
		"sellerId":    userID, 

	}

	sellerCollection := configs.GetCollection(client, "seller-products")
	_, err = sellerCollection.InsertOne(c.Context(), sellerProduct)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add product to seller-products"})
	}

	productCollection := configs.GetCollection(client, "products")
	_, err = productCollection.InsertOne(c.Context(), product)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to add product to products"})
	}

	log.Println("✅ Ürün başarıyla eklendi!")

	getSellerProductsFromDB(uid.Hex())

	c.Set("Content-Type", "text/html")
    return c.Send([]byte("<div>" + description + "</div>"))
}

func getProductsFromDB() ([]Product, error) {
	client := configs.DB
	collection := configs.GetCollection(client, "products")

	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch products: %v", err)
	}
	defer cursor.Close(context.TODO())

	var products []Product
	if err := cursor.All(context.TODO(), &products); err != nil {
		return nil, fmt.Errorf("failed to decode products: %v", err)
	}

	return products, nil
}

type User struct {
	Id       primitive.ObjectID `json:"id" bson:"_id"`
	Username string             `json:"username" bson:"Username"`
	Password string             `json:"password" bson:"Password"`
	Role     string             `json:"role" bson:"role"`
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
	UserID      primitive.ObjectID `json:"user_id" bson:"user_id"`
	ProductID   primitive.ObjectID `json:"product_id" bson:"product_id"` // ProductID alanını ekleyin

}

func getUsersFromDB() ([]User, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "users")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		log.Println("Error fetching users:", err)
		return nil, err
	}
	defer cursor.Close(nil)

	var users []User
	if err := cursor.All(nil, &users); err != nil {

		log.Println("Error decoding users:", err)

		return nil, err
	}

	log.Println("Fetched users:", users)
	return users, nil
}
func getSellerOrdersFromDB(c *fiber.Ctx) error {
	
	username := c.Locals("username").(string)

	client := configs.DB
	usersCollection := configs.GetCollection(client, "users")

	var seller User
	err := usersCollection.FindOne(context.TODO(), bson.M{"username": username, "role": "seller"}).Decode(&seller)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Seller not found"})
	}

	productsCollection := configs.GetCollection(client, "products")
	cursor, err := productsCollection.Find(context.TODO(), bson.M{"seller_id": seller.Id})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch seller's products"})
	}
	defer cursor.Close(context.TODO())

	var sellerProducts []Product
	if err := cursor.All(context.TODO(), &sellerProducts); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode products"})
	}

	var productIDs []primitive.ObjectID
	for _, product := range sellerProducts {
		oid, err := primitive.ObjectIDFromHex(product.ID) // product.ID'yi primitive.ObjectID'ye çevirin
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid product ID format"})
		}
		productIDs = append(productIDs, oid)
	}

	ordersCollection := configs.GetCollection(client, "orders")
	filter := bson.M{"product_id": bson.M{"$in": productIDs}}
	orderCursor, err := ordersCollection.Find(context.TODO(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch orders"})
	}
	defer orderCursor.Close(context.TODO())

	var sellerOrders []SellerOrder
	for orderCursor.Next(context.TODO()) {
		var order Order
		if err := orderCursor.Decode(&order); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode orders"})
		}

		sellerOrders = append(sellerOrders, SellerOrder{
			Id:        order.Id,
			Username:  order.Username,
			Name:      order.Name,
			Price:     order.Price,
			Quantity:  order.Quantity,
			ProductID: order.ProductID,
		})
	}

	return c.Render("order", fiber.Map{
		"SellerOrder": sellerOrders,
	})
}

func getOrdersFromDB() ([]Order, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "orders")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(nil)

	var orders []Order
	if err := cursor.All(nil, &orders); err != nil {
		return nil, err
	}

	return orders, nil
}

func getUserCart(c *fiber.Ctx) error {
	username := c.Locals("username").(string)

	client := configs.DB
	collection := configs.GetCollection(client, "carts")

	cursor, err := collection.Find(context.TODO(), bson.M{"UserID": username})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch cart items"})
	}
	defer cursor.Close(context.TODO())

	var cartItems []Cart
	if err := cursor.All(context.TODO(), &cartItems); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode cart items"})
	}

	return c.JSON(cartItems)
}

func getCartProducts(c *fiber.Ctx) error {
	cursor, _ := cartCollection.Find(context.TODO(), bson.M{})
	var cartItems []bson.M
	cursor.All(context.TODO(), &cartItems)

	return c.JSON(cartItems)
}

func removeFromCart(c *fiber.Ctx) error {
	name := c.FormValue("name")
	if name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Product name is required"})
	}

	username := c.Query("username")
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "username is required"})
	}

	client := configs.DB
	collection := configs.GetCollection(client, "carts")

	var existingCartItem Cart
	err := collection.FindOne(nil, bson.M{"name": name}).Decode(&existingCartItem)

	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Item not found in cart"})
	}

	if existingCartItem.Quantity > 1 {
		update := bson.M{"$inc": bson.M{"quantity": -1}}
		_, err = collection.UpdateOne(nil, bson.M{"name": name}, update)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update cart item"})
		}
	} else {
		// bir taneyse direkt sil
		_, err = collection.DeleteOne(nil, bson.M{"name": name})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to remove item from cart"})
		}
	}
	return c.Redirect(fmt.Sprintf("/carts?username=%s", username))
}

func getSellerOrderFromDB() ([]SellerOrder, error) {

	client := configs.DB
	collection := configs.GetCollection(client, "seller-orders")

	cursor, err := collection.Find(nil, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var sellerorders []SellerOrder
	if err := cursor.All(context.TODO(), &sellerorders); err != nil {
		return nil, err
	}
	return sellerorders, nil
}

func getCartItems(c *fiber.Ctx) error {
	username, ok := c.Locals("Username").(string)
	log.Printf("Cart Page - Username from locals: %v, OK: %v", username, ok)

	if !ok || username == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	client := configs.DB
	collection := configs.GetCollection(client, "carts")

	cursor, err := collection.Find(context.TODO(), bson.M{"username": username})
	if err != nil {
		log.Println("Sepet verisi alınamadı:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve cart items"})
	}

	var cartItems []Cart
	if err = cursor.All(context.TODO(), &cartItems); err != nil {
		log.Println("Sepet verisini maplerken hata oluştu:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to map cart items"})
	}

	if len(cartItems) == 0 {
		log.Println("Kullanıcının sepetinde ürün yok.")
		return c.Render("cart", fiber.Map{"CartItems": nil})
	}

	log.Printf("Sepette %d ürün var.", len(cartItems))
	return c.Render("cart", fiber.Map{"CartItems": cartItems})
}

var productCollection *mongo.Collection
var cartCollection *mongo.Collection

func connectMongoDB() {
	// ✅ **MongoDB bağlantısını oluştur**
	var err error
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")

	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal("MongoDB bağlantısı başarısız! Hata: ", err)
	}

	// ✅ **MongoDB bağlantısının çalıştığını kontrol et**
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal("MongoDB çalışmıyor! Lütfen kontrol et.", err)
	}

	log.Println("MongoDB bağlantısı başarılı!")
}


func main() {

	engine := html.New("./templates", ".html")

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	connectMongoDB()

	app.Use(logger.New())
	app.Use(cors.New())

	app.Use(func(c *fiber.Ctx) error {
		path := c.Path()         // Kullanıcının gitmek istediği URL
		userID := c.Cookies("userID") // Kullanıcının çerezinden userID'yi al
	
		if userID == "" || path == "/" || path == "/login"  || path == "/logout" {
			return c.Next()
		}
	
		if c.Query("id") == "" {
			newURL := fmt.Sprintf("%s?id=%s", path, userID)
			return c.Redirect(newURL, fiber.StatusFound) // Kullanıcıyı yeni URL'ye yönlendir
		}
	
		return c.Next()
	})

	app.Static("/", "templates")


// 📌 İlk olarak login.html göster
app.Get("/", loginPageHandler)

// 📌 Kullanıcı işlemleri
app.Get("/login", loginPageHandler)
app.Post("/login", loginHandler)
app.Get("/register", registerPageHandler)
app.Post("/register", registerHandler)


	/*
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("register", nil) 
	}) */

	/*
	app.Get("/register", func(c *fiber.Ctx) error {
		return c.Render("register", nil) 
	}) */

	app.Post("/cart", JWTMiddleware(), addToCart)
	app.Get("/cart", JWTMiddleware(), getUserCart)

	app.Use(AuthMiddleware)

	app.Post("/logout", logoutHandler)

	
	app.Get("/add-products", func(c *fiber.Ctx) error {

		return c.Render("add-products", nil)

	})
	
	//alttakini ekledim
	app.Post("/add-products", addProduct)

	app.Get("/api/products", func(c *fiber.Ctx) error {
		products, err := getProductsFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch products from the database",
			})
		}
		return c.JSON(products)
	})

	app.Get("/products", func(c *fiber.Ctx) error {
		userID := c.Cookies("userID")
		role := c.Cookies("role") // Kullanıcının rolünü al
	
		products, err := getProductsFromDB() // Ürünleri getir
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch products from the database",
			})
		}
	
		return c.Render("products", fiber.Map{
			"Products": products,
			"UserID":   userID,
			"UserRole": role, // Burada "Role" değil, "UserRole" olarak ekliyoruz!
		})
	})
	

	app.Get("/my-products", getMyProducts) 

	app.Get("/my-products", func(c *fiber.Ctx) error {
		return getMyProducts(c)
	})

	app.Get("/api/users", func(c *fiber.Ctx) error {
		user, err := getUsersFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch USERS from the database",
			})
		}
		return c.JSON(user)
	})

	app.Get("/users", func(c *fiber.Ctx) error {
		user, err := getUsersFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch Users from the database",
			})
		}
		return c.Render("user", fiber.Map{
			"Users": user,
		})
	})

	app.Get("/carts", func(c *fiber.Ctx) error {
		return getCart(c)
	})

	app.Post("/remove-from-cart", removeFromCart)

	client, _ := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017")) // ?????

	productCollection = client.Database("myWebsiteAPI").Collection("products")
	cartCollection = client.Database("myWebsiteAPI").Collection("cart")


	
	app.Post("/add-to-cart", addToCart)

	//get i sonradan ben ekledim
	// Eğer yanlışlıkla GET isteği yapılırsa, kullanıcının products sayfasına yönlendirilmesini sağlarız.
app.Get("/add-to-cart", func(c *fiber.Ctx) error {
    log.Println("🚨 UYARI: GET /add-to-cart çağrıldı! Yanlış yönlendirme olabilir.")
    return c.Redirect("/products")
})

	app.Get("/carts", getCart)


	app.Get("/orders", func(c *fiber.Ctx) error {
		order, err := getOrdersFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch Orders from the database",
			})
		}
		return c.Render("order", fiber.Map{
			"Orders": order,
		})
	})


	app.Get("/api/orders", func(c *fiber.Ctx) error {
		order, err := getOrdersFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch ORDERS from the database",
			})
		}
		return c.JSON(order)
	})

	app.Get("/my-orders", func(c *fiber.Ctx) error {
		sellerorder, err := getSellerOrderFromDB()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to fetch Seller Orders from the database",
			})
		}
		return c.Render("seller-orders", fiber.Map{
			"SellerOrder": sellerorder,
		})
	})

	app.Get("/my-orders", getSellerOrdersFromDB)

	app.Post("/add-products", addProduct)

	app.Post("/upload", func(c *fiber.Ctx) error {
		file, err := c.FormFile("image")
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "No file uploaded"})
		}

		fileData, err := file.Open()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
		}
		defer fileData.Close()

		client := configs.DB
		bucket, err := gridfs.NewBucket(client.Database("myWebsiteAPI"))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create GridFS bucket"})
		}

		uploadStream, err := bucket.OpenUploadStream(file.Filename)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to open upload stream"})
		}
		defer uploadStream.Close()

		if _, err := io.Copy(uploadStream, fileData); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to copy file data"})
		}

		imageID := uploadStream.FileID.(primitive.ObjectID)
		imageURL := fmt.Sprintf("/file/%s", imageID.Hex())

		product := new(SellerProduct)
		if err := c.BodyParser(product); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid product data"})
		}

		product.ImageURL = imageURL

		productsCollection := client.Database("myWebsiteAPI").Collection("seller-products")
		_, err = productsCollection.InsertOne(c.Context(), product)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save product"})
		}

		return c.Redirect("/my-products")
	})

	app.Get("/file/:id", func(c *fiber.Ctx) error {
		id := c.Params("id")

		client := configs.DB
		collection := client.Database("myWebsiteAPI").Collection("images")

		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid file ID"})
		}

		var result struct {
			FileName string `bson:"fileName"`
			Data     []byte `bson:"data"`
		}

		err = collection.FindOne(c.Context(), bson.M{"_id": objectID}).Decode(&result)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "File not found"})
		}

		c.Set("Content-Type", "image/png") //jpeg de olabilir buna bir bak
		return c.SendStream(bytes.NewReader(result.Data), -1)
	})

	log.Println("Server is running on 0.0.0.0:5000")
	err := app.Listen(":5000")
	if err != nil {
		log.Fatal(err)

	}

}