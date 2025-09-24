package pkg

import (
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/kljensen/snowball"
)

// ExtractKeywords extracts the 3 most frequent nouns from text
func ExtractKeywords(text string) []string {
	// Clean and normalize text
	cleanedText := cleanText(text)

	// Tokenize text into words
	words := tokenizeText(cleanedText)

	// Filter for nouns (simplified approach)
	nouns := filterNouns(words)

	// Count word frequencies
	wordCounts := countWords(nouns)

	// Sort by frequency and return top 3
	return getTopKeywords(wordCounts, 3)
}

// cleanText removes punctuation and normalizes text
func cleanText(text string) string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove extra whitespace
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	// Remove common punctuation but keep apostrophes for contractions
	text = regexp.MustCompile(`[^\w\s']+`).ReplaceAllString(text, " ")

	return text
}

// tokenizeText splits text into individual words
func tokenizeText(text string) []string {
	words := strings.Fields(text)
	var filteredWords []string

	for _, word := range words {
		// Remove apostrophes and filter out very short words
		word = strings.Trim(word, "'")
		if len(word) > 2 && isAlphabetic(word) {
			filteredWords = append(filteredWords, word)
		}
	}

	return filteredWords
}

// isAlphabetic checks if a word contains only alphabetic characters
func isAlphabetic(word string) bool {
	for _, r := range word {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// filterNouns attempts to identify nouns using simple heuristics
func filterNouns(words []string) []string {
	var nouns []string

	// Common stop words to exclude
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true, "but": true,
		"in": true, "on": true, "at": true, "to": true, "for": true, "of": true,
		"with": true, "by": true, "from": true, "up": true, "about": true, "into": true,
		"through": true, "during": true, "before": true, "after": true, "above": true,
		"below": true, "between": true, "among": true, "is": true, "are": true, "was": true,
		"were": true, "be": true, "been": true, "being": true, "have": true, "has": true,
		"had": true, "do": true, "does": true, "did": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true, "can": true,
		"this": true, "that": true, "these": true, "those": true, "i": true, "you": true,
		"he": true, "she": true, "it": true, "we": true, "they": true, "me": true,
		"him": true, "her": true, "us": true, "them": true, "my": true, "your": true,
		"his": true, "its": true, "our": true, "their": true,
	}

	for _, word := range words {
		// Skip stop words
		if stopWords[word] {
			continue
		}

		// Skip very short words
		if len(word) < 3 {
			continue
		}

		// Skip words that are too long (likely not nouns)
		if len(word) > 20 {
			continue
		}

		// Simple heuristic: words ending in common noun suffixes
		if hasNounSuffix(word) {
			nouns = append(nouns, word)
			continue
		}

		// Include words that are likely nouns based on length and character patterns
		if len(word) >= 4 && len(word) <= 12 {
			nouns = append(nouns, word)
		}
	}

	return nouns
}

// hasNounSuffix checks if a word has common noun suffixes
func hasNounSuffix(word string) bool {
	nounSuffixes := []string{
		"tion", "sion", "ness", "ment", "ity", "ty", "er", "or", "ist", "ism",
		"ing", "age", "ure", "ance", "ence", "hood", "ship", "dom", "th",
	}

	for _, suffix := range nounSuffixes {
		if strings.HasSuffix(word, suffix) {
			return true
		}
	}

	return false
}

// countWords counts the frequency of each word
func countWords(words []string) map[string]int {
	wordCounts := make(map[string]int)

	for _, word := range words {
		// Stem the word to group similar words together
		stemmed, err := snowball.Stem(word, "english", true)
		if err != nil {
			// If stemming fails, use the original word
			stemmed = word
		}

		wordCounts[stemmed]++
	}

	return wordCounts
}

// getTopKeywords returns the top N most frequent keywords
func getTopKeywords(wordCounts map[string]int, n int) []string {
	// Convert map to slice of pairs
	type wordCount struct {
		word  string
		count int
	}

	var pairs []wordCount
	for word, count := range wordCounts {
		pairs = append(pairs, wordCount{word, count})
	}

	// Sort by count (descending), then by word (ascending) for consistency
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].word < pairs[j].word
		}
		return pairs[i].count > pairs[j].count
	})

	// Extract top N words
	var keywords []string
	for i := 0; i < n && i < len(pairs); i++ {
		keywords = append(keywords, pairs[i].word)
	}

	// If we don't have enough keywords, pad with generic ones
	genericKeywords := []string{"content", "information", "text", "data", "analysis"}
	for len(keywords) < n {
		keyword := genericKeywords[len(keywords)%len(genericKeywords)]
		// Avoid duplicates
		if !contains(keywords, keyword) {
			keywords = append(keywords, keyword)
		} else {
			// If we've exhausted generic keywords, break
			break
		}
	}

	return keywords
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// CalculateConfidence calculates a confidence score based on text analysis
func CalculateConfidence(text string, extractedData map[string]interface{}) float64 {
	confidence := 0.5 // Base confidence

	// Adjust based on text length
	if len(text) > 100 {
		confidence += 0.1
	}
	if len(text) > 500 {
		confidence += 0.1
	}

	// Adjust based on extracted data quality
	if title, ok := extractedData["title"].(string); ok && len(title) > 0 {
		confidence += 0.1
	}

	if summary, ok := extractedData["summary"].(string); ok && len(summary) > 20 {
		confidence += 0.1
	}

	if topics, ok := extractedData["topics"].([]string); ok && len(topics) == 3 {
		confidence += 0.1
	}

	// Ensure confidence is within bounds
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence
}

// PreprocessText prepares text for LLM analysis
func PreprocessText(text string) string {
	// Remove excessive whitespace
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	// Remove excessive punctuation
	text = regexp.MustCompile(`[.]{3,}`).ReplaceAllString(text, "...")
	text = regexp.MustCompile(`[!]{2,}`).ReplaceAllString(text, "!")
	text = regexp.MustCompile(`[?]{2,}`).ReplaceAllString(text, "?")

	return text
}
