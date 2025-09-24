package internal

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type CoreTestSuite struct {
	suite.Suite
}

func (suite *CoreTestSuite) TestCoreSingleton() {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "should return same instance on multiple calls",
			expected: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Reset singleton for clean test
			instance = nil
			once = sync.Once{}

			instance1 := GetInstance()
			instance2 := GetInstance()

			assert.Equal(suite.T(), instance1, instance2, "GetInstance should return the same instance (singleton pattern)")
			assert.NotNil(suite.T(), instance1, "GetInstance should not return nil")
			assert.NotNil(suite.T(), instance2, "GetInstance should not return nil")
		})
	}
}

func (suite *CoreTestSuite) TestCoreSingletonConcurrency() {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "should handle concurrent access safely",
			expected: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Reset singleton for clean test
			instance = nil
			once = sync.Once{}

			// Test concurrent access
			done := make(chan bool, 10)
			instances := make([]*Core, 10)

			for i := 0; i < 10; i++ {
				go func(index int) {
					instances[index] = GetInstance()
					done <- true
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < 10; i++ {
				<-done
			}

			// All instances should be the same
			firstInstance := instances[0]
			for i := 1; i < 10; i++ {
				assert.Equal(suite.T(), firstInstance, instances[i], "All concurrent calls should return the same instance")
			}
		})
	}
}

func (suite *CoreTestSuite) TestCoreInitialState() {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "should have nil components initially",
			expected: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Reset singleton for clean test
			instance = nil
			once = sync.Once{}

			core := GetInstance()

			assert.Nil(suite.T(), core.Config(), "Config should be nil initially")
			assert.Nil(suite.T(), core.Logger(), "Logger should be nil initially")
			assert.Nil(suite.T(), core.Dao(), "DAO should be nil initially")
			assert.Nil(suite.T(), core.Service(), "Service should be nil initially")
			assert.Nil(suite.T(), core.Handler(), "Handler should be nil initially")
			assert.Nil(suite.T(), core.Server(), "Server should be nil initially")
		})
	}
}

func TestCoreTestSuite(t *testing.T) {
	suite.Run(t, new(CoreTestSuite))
}
