package service

import (
	"context"
	"errors"

	"github.com/superirale/kya-gateway/internal/delegation"
	"github.com/superirale/kya-gateway/internal/model"
	"github.com/superirale/kya-gateway/internal/storage"
)

func (s *Service) CreateDelegation(ctx context.Context, consumerRef string, r delegation.Request) (model.Delegation, error) {
	a, err := s.Store.GetAgent(ctx, r.AgentID)
	if errors.Is(err, storage.ErrNotFound) {
		return model.Delegation{}, invalid("agent is not registered")
	} else if err != nil {
		return model.Delegation{}, err
	}
	if a.Status != model.AgentActive {
		return model.Delegation{}, invalid("agent is disabled")
	}
	d, err := s.Issuer.Issue(r, consumerRef, s.now())
	if err != nil {
		return model.Delegation{}, invalid(err.Error())
	}
	if err := s.Store.CreateDelegation(ctx, d); err != nil {
		return model.Delegation{}, err
	}
	s.audit(ctx, "delegation", d.ID, "delegation.created", d.Claims.MerchantID, d.Claims)
	return d, nil
}

func (s *Service) ListDelegations(ctx context.Context, consumerRef string) ([]model.Delegation, error) {
	return s.Store.ListDelegations(ctx, consumerRef)
}

func (s *Service) RevokeDelegation(ctx context.Context, consumerRef, id string) (model.Delegation, error) {
	d, err := s.Store.RevokeDelegation(ctx, id, consumerRef, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		return d, notFound("delegation not found")
	}
	if err == nil {
		s.audit(ctx, "delegation", d.ID, "delegation.revoked", d.Claims.MerchantID, map[string]string{"delegation_id": id})
	}
	return d, err
}
