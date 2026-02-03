package redis

import (
	"context"
	"time"

	"github.com/blcvn/backend/services/auth-service/common/errors"
	"github.com/redis/go-redis/v9"
)

type tokenRepository struct {
	client *redis.Client
	ctx    context.Context
}

func NewTokenRepository(client *redis.Client) *tokenRepository {
	return &tokenRepository{
		client: client,
		ctx:    context.Background(),
	}
}

func (r *tokenRepository) BlacklistAccessToken(token string, expiration time.Duration) errors.BaseError {
	err := r.client.Set(r.ctx, "blacklist:access:"+token, "true", expiration).Err()
	if err != nil {
		return errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}
	return nil
}

func (r *tokenRepository) IsAccessTokenBlacklisted(token string) (bool, errors.BaseError) {
	val, err := r.client.Get(r.ctx, "blacklist:access:"+token).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, errors.NewBaseError(errors.INTERNAL_ERROR, err)
	}
	return val == "true", nil
}
