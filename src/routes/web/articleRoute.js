import express from 'express';
import cache from '../../config/cache.js';
import {
    getArticlesById,
    getArticlesSameCategory,
    incrementArticleViews,
    getArticleCountByAuthor,
} from "../../services/articleService.js";
import { getCategoryName } from "../../services/categoryService.js";
import { getTags, getTagName } from "../../services/tagService.js";
import { findUser } from '../../services/userService.js';

const router = express.Router();

router.get("/article/:id", async (req, res) => {
    try {
        const articleId = req.params.id;
        const cacheKey = `article_${articleId}`;

        // Check cache
        const cachedData = cache.get(cacheKey);
        if (cachedData) {
            return res.render("pages/ArticlePage", cachedData);
        }

        // Get article by ID
        const response = await getArticlesById(articleId);

        if (!response.success) {
            return res.status(404).send(response.error);
        }

        const article = response.data;

        // Get category names
        const categoryNames = await Promise.all(
            article.category.map((catId) => getCategoryName(catId))
        );

        const tagsResponse = await getTags();

        // Get tag names
        const tagNames = await Promise.all(
            article.tags.map((tagId) => getTagName(tagId))
        );

        const relatedResponse = await getArticlesSameCategory(
            article.category[0],
            articleId
        );

        if (!relatedResponse.success) {
            return res
                .status(500)
                .json({ success: false, error: relatedResponse.error });
        }

        // Get author details
        const authors = await Promise.all(
          article.author.map((authorId) => findUser(authorId))
        );

        const articleCount = await Promise.all(
            article.author.map((authorId) => getArticleCountByAuthor(authorId))
        );

        const articleData = {
            title: article.name,
            article: {
                ...article,
                categoryNames,
                tagNames,
                authors,
                articleCount,
            },
            articleSameCategory: relatedResponse.data,
            tags: tagsResponse.data,
        };

        // Cache the data
        cache.set(cacheKey, articleData);

        incrementArticleViews(articleId);

        res.render("pages/ArticlePage", articleData);
    } catch (error) {
        console.error("Route handler error:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

export default router;