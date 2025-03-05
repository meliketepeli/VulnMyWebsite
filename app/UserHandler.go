package app

import (
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"net/http"
	"myWebsite-main/models"
	"myWebsite-main/services"
)

type UserHandler struct {
	Service services.UserService
}

func (h UserHandler) CreateUser(c *fiber.Ctx) error {

	var user models.User
	// json gelen veriyi struct turune donusturme yapıyoruz
	if err := c.BodyParser(&user); err != nil {
		return c.Status(http.StatusBadRequest).JSON(err.Error())
	}

	result, err := h.Service.UserInsert(user)

	if err != nil || result.Status == false {
		return err
	}

	return c.Status(http.StatusCreated).JSON(result)
}

// service verilerini handlerdan alıyor
func (h UserHandler) GetAllUser(c *fiber.Ctx) error {

	result, err := h.Service.UserGetAll()

	if err != nil {
		log.Println("Ürünler alınırken hata oluştu:", err)
		return c.Status(http.StatusInternalServerError).JSON(err.Error())
	}

	return c.Status(http.StatusOK).JSON(result)

	// Kullanıcıları HTML şablonuna aktar
	return c.Render("user.html", fiber.Map{
		"User": result,
	})

}

func (h UserHandler) DeleteUser(c *fiber.Ctx) error {

	// id buradan string geliyor
	query := c.Params("id")
	// string id yi hex e donusturme
	cnv, _ := primitive.ObjectIDFromHex(query)

	result, err := h.Service.UserDelete(cnv)

	if err != nil || result == false {

		//kendi modelimizi oluşturmak gibi düşünebiliriz (buna bak bence)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"State": false})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"State": true})
}

func (h UserHandler) LoginUser(c *fiber.Ctx) error {
    var loginData map[string]interface{} // Struct yerine MAP kullanıyoruz!

    if err := c.BodyParser(&loginData); err != nil {
        return c.Status(http.StatusBadRequest).JSON(err.Error())
    }

    username, uExists := loginData["username"]
    password, pExists := loginData["password"]

    if !uExists || !pExists {
        return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Username and password required"})
    }

    user, err := h.Service.UserLogin(username, password)

    if err != nil || user == nil {
        return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"message": "Geçersiz giriş!"})
    }

    return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Giriş başarılı!", "user": user.Username})
}

