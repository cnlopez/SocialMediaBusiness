package main

import (
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// Estructura de datos para el usuario
type User struct {
	Username string
	Password string
}

// Clave secreta para firmar los tokens JWT
var jwtSecret = []byte("mi_clave_secreta")

func main() {
	r := gin.Default()

	// Ruta para el inicio de sesión
	r.POST("/login", handleLogin)

	// Ruta protegida por autenticación
	//r.GET("/protected", authMiddleware(), handleProtected)
	r.GET("/protected", authMiddleware())

	r.Run(":8080")
}

// Manejador para el inicio de sesión
func handleLogin(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Credenciales inválidas"})
		return
	}

	// Verificar las credenciales del usuario
	if credentials.Username == "usuario" && credentials.Password == "contraseña" {
		// Generar el token de acceso
		token := generateToken(credentials.Username)

		// Devolver el token al cliente
		c.JSON(http.StatusOK, gin.H{"token": token})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciales inválidas"})
	}
}

// Generar un token JWT
func generateToken(username string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Expira en 24 horas
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Fatal(err)
	}

	return tokenString
}

// Middleware de autenticación
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		// Verificar el token de acceso
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
			c.Abort()
			return
		}

		// Token válido, continuar con la siguiente función de middleware o el manejador
		c.Next()
	}
}
