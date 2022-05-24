package oauth2xorm

import (
	"context"
	"fmt"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	jsoniter "github.com/json-iterator/go"
	"xorm.io/xorm"
)

type ClientStore struct {
	db                *xorm.Engine
	tableName         string
	initTableDisabled bool
	maxLifetime       time.Duration
	maxOpenConns      int
	maxIdleConns      int
}

// ClientStoreItem data item
type ClientStoreItem struct {
	ID     string `xorm:"id"`
	Secret string `xorm:"secret"`
	Domain string `xorm:"domain"`
	Data   string `xorm:"data"`
}

// NewClientStore creates xorm mysql store instance
func NewClientStore(db *xorm.Engine, options ...ClientStoreOption) (*ClientStore, error) {
	store := &ClientStore{
		db:           db,
		tableName:    "oauth2_client",
		maxLifetime:  time.Hour * 2,
		maxOpenConns: 50,
		maxIdleConns: 25,
	}

	for _, o := range options {
		o(store)
	}

	var err error
	if !store.initTableDisabled {
		err = store.initTable()
	}

	if err != nil {
		return store, err
	}

	store.db.SetMaxOpenConns(store.maxOpenConns)
	store.db.SetMaxIdleConns(store.maxIdleConns)
	store.db.SetConnMaxLifetime(store.maxLifetime)

	return store, err
}

func (s *ClientStore) initTable() error {
	query := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id VARCHAR(16) NOT NULL PRIMARY KEY,
		secret VARCHAR(255) NOT NULL,
		domain VARCHAR(255) NOT NULL,
		data TEXT NOT NULL
	  );
`, s.tableName)

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

// GetByID retrieves and returns client information by id
func (s *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	if id == "" {
		return nil, nil
	}

	item := &ClientStoreItem{
		ID: id,
	}

	_, err := s.db.Table(s.tableName).Get(item)
	if err != nil {
		return nil, err
	}
	return &models.Client{
		ID:     item.ID,
		Secret: item.Secret,
		Domain: item.Domain,
		UserID: "", // dont support user create a client
	}, nil
}

// Create creates and stores the new client information
func (s *ClientStore) Create(info oauth2.ClientInfo) error {

	data, err := jsoniter.Marshal(info)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(fmt.Sprintf("INSERT INTO %s (id, secret, domain, data) VALUES (?,?,?,?)", s.tableName),
		info.GetID(),
		info.GetSecret(),
		info.GetDomain(),
		string(data),
	)
	if err != nil {
		return err
	}

	return nil
}
