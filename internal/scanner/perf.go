package scanner

import (
	"os"
	"sync"
)

// IsBinaryFile checks the first 512 bytes for null characters.
// Binary files are skipped during scanning.
func IsBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	for _, b := range buf[:n] {
		if b == 0 {
			return true
		}
	}
	return false
}

// LRUCache is a simple LRU cache for parsed AST results.
type LRUCache struct {
	capacity int
	items    map[string]*cacheEntry
	order    []string
	mu       sync.Mutex
}

type cacheEntry struct {
	data interface{}
	size int
}

// NewLRUCache creates a cache with the given capacity (number of entries).
func NewLRUCache(capacity int) *LRUCache {
	if capacity <= 0 {
		capacity = 256
	}
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*cacheEntry),
	}
}

// Get retrieves an entry from the cache.
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[key]
	if !ok {
		return nil, false
	}
	// Move to front
	c.moveToFront(key)
	return entry.data, true
}

// Put adds an entry to the cache, evicting the LRU if at capacity.
func (c *LRUCache) Put(key string, data interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[key]; ok {
		c.items[key].data = data
		c.moveToFront(key)
		return
	}
	if len(c.items) >= c.capacity {
		// Evict LRU (last in order)
		evict := c.order[len(c.order)-1]
		delete(c.items, evict)
		c.order = c.order[:len(c.order)-1]
	}
	c.items[key] = &cacheEntry{data: data}
	c.order = append([]string{key}, c.order...)
}

func (c *LRUCache) moveToFront(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append([]string{key}, c.order...)
			return
		}
	}
}

// Size returns the number of cached entries.
func (c *LRUCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
