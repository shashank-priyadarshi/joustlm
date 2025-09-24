package pkg

import (
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/kljensen/snowball"
)

func ExtractKeywords(text string) []string {
	cleanedText := cleanText(text)

	words := tokenizeText(cleanedText)

	nouns := filterNouns(words)

	wordCounts := countWords(nouns)

	return getTopKeywords(wordCounts, 3)
}

func cleanText(text string) string {
	text = strings.ToLower(text)

	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	text = regexp.MustCompile(`[^\w\s']+`).ReplaceAllString(text, " ")

	return text
}

func tokenizeText(text string) []string {
	words := strings.Fields(text)
	var filteredWords []string

	for _, word := range words {
		word = strings.Trim(word, "'")
		if len(word) > 2 && isAlphabetic(word) {
			filteredWords = append(filteredWords, word)
		}
	}

	return filteredWords
}

func isAlphabetic(word string) bool {
	for _, r := range word {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func filterNouns(words []string) []string {
	var nouns []string

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
		if stopWords[word] {
			continue
		}

		if len(word) < 3 {
			continue
		}

		if len(word) > 20 {
			continue
		}

		if hasNounSuffix(word) {
			nouns = append(nouns, word)
			continue
		}

		if len(word) >= 4 && len(word) <= 12 {
			nouns = append(nouns, word)
		}
	}

	return nouns
}

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

func countWords(words []string) map[string]int {
	wordCounts := make(map[string]int)

	for _, word := range words {
		stemmed, err := snowball.Stem(word, "english", true)
		if err != nil {
			stemmed = word
		}

		wordCounts[stemmed]++
	}

	return wordCounts
}

func getTopKeywords(wordCounts map[string]int, n int) []string {
	type wordCount struct {
		word  string
		count int
	}

	var pairs []wordCount
	for word, count := range wordCounts {
		pairs = append(pairs, wordCount{word, count})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].word < pairs[j].word
		}
		return pairs[i].count > pairs[j].count
	})

	var keywords []string
	for i := 0; i < n && i < len(pairs); i++ {
		keywords = append(keywords, pairs[i].word)
	}

	genericKeywords := []string{"content", "information", "text", "data", "analysis"}
	for len(keywords) < n {
		keyword := genericKeywords[len(keywords)%len(genericKeywords)]
		if !contains(keywords, keyword) {
			keywords = append(keywords, keyword)
		} else {
			break
		}
	}

	return keywords
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func CalculateConfidence(text string, extractedData map[string]interface{}) float64 {
	confidence := 0.5

	if len(text) > 100 {
		confidence += 0.1
	}
	if len(text) > 500 {
		confidence += 0.1
	}

	if title, ok := extractedData["title"].(string); ok && len(title) > 0 {
		confidence += 0.1
	}

	if summary, ok := extractedData["summary"].(string); ok && len(summary) > 20 {
		confidence += 0.1
	}

	if topics, ok := extractedData["topics"].([]string); ok && len(topics) == 3 {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence
}

func PreprocessText(text string) string {
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	text = regexp.MustCompile(`[.]{3,}`).ReplaceAllString(text, "...")
	text = regexp.MustCompile(`[!]{2,}`).ReplaceAllString(text, "!")
	text = regexp.MustCompile(`[?]{2,}`).ReplaceAllString(text, "?")

	return text
}
