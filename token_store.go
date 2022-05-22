package oauth2xorm

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"xorm.io/xorm"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	jsoniter "github.com/json-iterator/go"
)

// StoreItem data item
type StoreItem struct {
	ID        int64  `xorm:"id"`
	ClientId  string `xorm:"client_id"`
	UserId    int64  `xorm:"user_id"`
	ExpiredAt int64  `xorm:"expired_at"`
	Code      string `xorm:"code"`
	Access    string `xorm:"access"`
	Refresh   string `xorm:"refresh"`
	Data      string `xorm:"data"`
}

// NewConfig create mysql configuration instance
func NewConfig(dsn string) *Config {
	return &Config{
		DSN:          dsn,
		MaxLifetime:  time.Hour * 2,
		MaxOpenConns: 50,
		MaxIdleConns: 25,
	}
}

// Config mysql configuration
type Config struct {
	DSN          string
	MaxLifetime  time.Duration
	MaxOpenConns int
	MaxIdleConns int
}

// NewDefaultStore create mysql store instance
func NewDefaultStore(config *Config, autoMigrate bool) *Store {
	return NewStore(config, "", 0, autoMigrate)
}

// NewStore create mysql store instance,
// config mysql configuration,
// tableName table name (default oauth2_token),
// GC time interval (in seconds, default 600)
func NewStore(config *Config, tableName string, gcInterval int, autoMigrate bool) *Store {
	db, err := xorm.NewEngine("mysql", config.DSN)

	if err != nil {
		panic(err)
	}

	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.MaxLifetime)

	return NewStoreWithDB(db, tableName, gcInterval, autoMigrate)
}

// NewStoreWithDB create mysql store instance,
// db sql.DB,
// tableName table name (default oauth2_token),
// GC time interval (in seconds, default 600)
func NewStoreWithDB(db *xorm.Engine, tableName string, gcInterval int, autoMigrate bool) *Store {
	store := &Store{
		db:        db,
		tableName: "oauth2_token",
		stdout:    os.Stderr,
	}

	if tableName != "" {
		store.tableName = tableName
	}

	interval := 600
	if gcInterval > 0 {
		interval = gcInterval
	}

	store.ticker = time.NewTicker(time.Second * time.Duration(interval))

	if autoMigrate {
		stmt := fmt.Sprintf(`
					CREATE TABLE IF NOT EXISTS %s (
					id int(10) unsigned NOT NULL AUTO_INCREMENT,
					code varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
					client_id varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL,
					user_id int unsigned NOT NULL,
					access varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
					refresh varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
					expired_at int(11) NOT NULL,
					data varchar(2048) COLLATE utf8mb4_unicode_ci NOT NULL,
					created_at timestamp default Now(),
					PRIMARY KEY (id),
					KEY idx_oauth2_token_code (code),
					KEY idx_oauth2_token_expired_at (expired_at),
					KEY idx_oauth2_token_access (access),
					KEY idx_oauth2_token_refresh (refresh)
				  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
				`, store.tableName)

		_, err := db.Exec(stmt)
		if err != nil {
			panic(err)
		}
	}

	go store.gc()
	return store
}

// Store mysql token store
type Store struct {
	tableName string
	db        *xorm.Engine
	stdout    io.Writer
	ticker    *time.Ticker
}

// SetStdout set error output
func (s *Store) SetStdout(stdout io.Writer) *Store {
	s.stdout = stdout
	return s
}

// Close close the store
func (s *Store) Close() {
	s.ticker.Stop()
	s.db.Close()
}

func (s *Store) gc() {
	for range s.ticker.C {
		s.clean()
	}
}

func (s *Store) clean() {
	now := time.Now().Unix()
	//query := fmt.Sprintf("SELECT COUNT(1) FROM %s WHERE expired_at<=? OR (code='' AND access='' AND refresh='')", s.tableName)
	//n, err := s.db.SelectInt(query, now)

	n, err := s.db.Where("expired_at >= ?", now).Or("code='' AND access='' AND refresh=''").Table(s.tableName).Count()
	if err != nil || n == 0 {
		if err != nil {
			s.errorf(err.Error())
		}
		return
	}

	_, err = s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE expired_at<=? OR (code='' AND access='' AND refresh='')", s.tableName), now)

	if err != nil {
		s.errorf(err.Error())
	}
}

func (s *Store) errorf(format string, args ...interface{}) {
	if s.stdout != nil {
		buf := fmt.Sprintf("[OAUTH2-MYSQL-ERROR]: "+format, args...)
		s.stdout.Write([]byte(buf))
	}
}

// Create create and store the new token information
func (s *Store) Create(ctx context.Context, info oauth2.TokenInfo) error {
	buf, _ := jsoniter.Marshal(info)
	userId, err := strconv.Atoi(info.GetUserID())
	if err != nil {
		s.errorf(err.Error())
		return err
	}
	item := &StoreItem{
		ClientId: info.GetClientID(),
		UserId:   int64(userId),
		Data:     string(buf),
	}

	if code := info.GetCode(); code != "" {
		item.Code = code
		item.ExpiredAt = info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()).Unix()
	} else {
		item.Access = info.GetAccess()
		item.ExpiredAt = info.GetAccessCreateAt().Add(info.GetAccessExpiresIn()).Unix()

		if refresh := info.GetRefresh(); refresh != "" {
			item.Refresh = info.GetRefresh()
			item.ExpiredAt = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Unix()
		}
	}
	_, err = s.db.Table(s.tableName).Insert(item)
	return err
}

// RemoveByCode delete the authorization code
func (s *Store) RemoveByCode(ctx context.Context, code string) error {
	query := fmt.Sprintf("UPDATE %s SET code='' WHERE code=? LIMIT 1", s.tableName)
	_, err := s.db.Exec(query, code)
	if err != nil {
		return nil
	}
	return err
}

// RemoveByAccess use the access token to delete the token information
func (s *Store) RemoveByAccess(ctx context.Context, access string) error {
	query := fmt.Sprintf("UPDATE %s SET access='' WHERE access=? LIMIT 1", s.tableName)
	_, err := s.db.Exec(query, access)
	if err != nil && err == sql.ErrNoRows {
		return nil
	}
	return err
}

// RemoveByRefresh use the refresh token to delete the token information
func (s *Store) RemoveByRefresh(ctx context.Context, refresh string) error {
	query := fmt.Sprintf("UPDATE %s SET refresh='' WHERE refresh=? LIMIT 1", s.tableName)
	_, err := s.db.Exec(query, refresh)
	if err != nil && err == sql.ErrNoRows {
		return nil
	}
	return err
}

func (s *Store) toTokenInfo(data string) oauth2.TokenInfo {
	var tm models.Token
	jsoniter.Unmarshal([]byte(data), &tm)
	return &tm
}

// GetByCode use the authorization code for token information data
func (s *Store) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	if code == "" {
		return nil, nil
	}

	//query := fmt.Sprintf("SELECT * FROM %s WHERE code=? LIMIT 1", s.tableName)
	//var item StoreItem
	item := StoreItem{Code: code}

	has, err := s.db.Table(s.tableName).Get(&item)
	if err != nil {
		return nil, err
	}

	if !has {
		return nil, nil
	}
	return s.toTokenInfo(item.Data), nil
}

// GetByAccess use the access token for token information data
func (s *Store) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	if access == "" {
		return nil, nil
	}

	//query := fmt.Sprintf("SELECT * FROM %s WHERE access=? LIMIT 1", s.tableName)
	//var item StoreItem

	item := StoreItem{Access: access}

	has, err := s.db.Table(s.tableName).Get(&item)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return s.toTokenInfo(item.Data), nil
}

// GetByRefresh use the refresh token for token information data
func (s *Store) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	if refresh == "" {
		return nil, nil
	}

	//query := fmt.Sprintf("SELECT * FROM %s WHERE refresh=? LIMIT 1", s.tableName)
	//var item StoreItem

	item := StoreItem{Refresh: refresh}
	has, err := s.db.Table(s.tableName).Get(&item)

	if err != nil {
		return nil, err
	}

	if !has {
		return nil, nil
	}

	return s.toTokenInfo(item.Data), nil
}
