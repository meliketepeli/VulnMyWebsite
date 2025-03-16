package app

import (
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"net/http"
	"myWebsite-main/services"
)

type CartHandler struct {
	Service services.UserService
}

func (h CartHandler) CreateCart(c *fiber.Ctx) error {

	var cart map[string]interface{}
	if err := c.BodyParser(&cart); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Cart created successfully",
		"cart":    cart,
	})
}

// service verilerini handlerdan alıyor
func (h CartHandler) GetAllCart(c *fiber.Ctx) error {

	result, err := h.Service.CartGetAll()

	if err != nil {
		log.Println("Cart alınırken hata oluştu:", err)
		return c.Status(http.StatusInternalServerError).JSON(err.Error())
	}

	return c.Status(http.StatusOK).JSON(result)

	// Sepeti HTML şablonuna aktarma kısmı
	return c.Render("cart.html", fiber.Map{
		"Cart": result,
	})

}

func (h CartHandler) DeleteCart(c *fiber.Ctx) error {

	// id buradan string geliyor
	query := c.Params("id")

	// string id yi hex e donusturme
	cnv, _ := primitive.ObjectIDFromHex(query)

	result, err := h.Service.CartDelete(cnv)

	if err != nil || result == false {

		//kendi modelimizi oluşturmak gibi düşünebiliriz (buna bak bence)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"State": false})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"State": true})
}
