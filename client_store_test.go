package oauth2xorm

import (
	"context"
	"fmt"
	"github.com/go-oauth2/oauth2/v4/models"
	_ "github.com/go-sql-driver/mysql"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"testing"
	"xorm.io/xorm"
)

const TBOauthClient = "oauth2_client"

func TestClientStoreCreate(t *testing.T) {
	db, _ := xorm.NewEngine("mysql", dsn)
	store, _ := NewClientStore(db, WithClientStoreTableName(TBOauthClient))

	clientInfo := &models.Client{
		ID:     "1_1",
		Secret: "2_2",
		Domain: "3_3",
		UserID: "4_4",
	}

	err := store.Create(clientInfo)
	assert.Nil(t, err)

	// tearDown
	stmt := fmt.Sprintf("delete from %s where id = ?", TBOauthClient)
	_, _ = db.Exec(stmt, clientInfo.ID)
}

func TestClientStoreGetByID(t *testing.T) {
	// Arrange
	db, _ := xorm.NewEngine("mysql", dsn)

	clientInfo := models.Client{
		ID:     "1_1",
		Secret: "2_2",
		Domain: "3_3",
		UserID: "4_4",
	}

	data, err := jsoniter.Marshal(clientInfo)

	_, _ = db.Exec(fmt.Sprintf("INSERT INTO %s (id, secret, domain, data) VALUES (?,?,?,?)", TBOauthClient),
		clientInfo.ID,
		clientInfo.Secret,
		clientInfo.Domain,
		string(data),
	)

	// Act
	store, _ := NewClientStore(db, WithClientStoreTableName(TBOauthClient))
	ctx := context.Background()
	ci, err := store.GetByID(ctx, "1_1")

	// Assert
	assert.Nil(t, err)
	assert.Equal(t, ci.GetID(), "1_1")

	// TearDown

	// tearDown
	stmt := fmt.Sprintf("delete from %s where id = ?", TBOauthClient)
	_, _ = db.Exec(stmt, clientInfo.ID)
}
