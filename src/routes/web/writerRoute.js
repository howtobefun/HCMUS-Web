import express from "express";
import { getArticlesByAuthor } from "../../services/articleService.js";
import { createArticle } from "../../services/articleService.js";
import { getTags } from "../../services/tagService.js";
import { getCategories } from "../../services/categoryService.js";
import { findUserByName, findUser } from "../../services/userService.js";
import cache from "../../config/cache.js";

const router = express.Router();

router.get("/my-articles", async (req, res) => {
  try {
    // const author = req.user.username;
    // const page = parseInt(req.query.page) || 1;

    // const userResponse = await findUserByName(author);
    // if (!userResponse.success) {
    //   return res.status(404).render("pages/404");
    // }

    // const articlesResponse = await getArticlesByAuthor(
    //   userResponse.data._id,
    //   page
    // );

    // if (!articlesResponse.success) {
    //   return res.status(500).json({ error: articlesResponse.error });
    // }

    // Get all tags
    const tagsResponse = await getTags();

    // Get all categories
    const categoriesResponse = await getCategories();

    const userId = req.user?._id;
    const user = req.user || (userId && (await findUser(userId))) || null;

    const pageData = {
      title: `Bài viết của tôi`,
      tags: tagsResponse.data,
      categories: categoriesResponse.data,
      //   articles: articlesResponse.data.articles,
      //   pagination: articlesResponse.data.pagination,
      user: user,
    };

    res.render("pages/MyPostPage", pageData);
  } catch (error) {
    console.error("My articles page error:", error);
  }
});

// get my-article/create

router.get("/my-articles/create", async (req, res) => {
  try {
    const tagsResponse = await getTags();
    const categoriesResponse = await getCategories();

    const userId = req.user?._id;
    const user = req.user || (userId && (await findUser(userId))) || null;

    // if user is not logged in, redirect to login page
    if (!user) {
      return res.redirect("/auth/login");
    }

    const articleCount = await getArticlesByAuthor(userId);

    const pageData = {
      title: "Tạo bài viết mới",
      tags: tagsResponse.data,
      categories: categoriesResponse.data,
      article: {
        title: "",
        author: "",
        abstract: "",
        content: "",
        is_premium: false,
      },
      user: user,
      articleCount: articleCount,
    };
    console.log(pageData);
    console.log(articleCount.data);

    res.render("pages/CreateArticlePage", pageData);
  } catch (error) {
    console.error("Create article page error:", error);
  }
});

router.post("/my-articles/create", async (req, res) => {
  console.log(1111);
  try {
    const {
      name,
      image,
      abstract,
      content,
      category,
      tags,
      isPremium,
      status,
      publishedAt,
    } = req.body;

    const tagsResponse = await getTags();
    const categoriesResponse = await getCategories();

    const userId = req.user?._id;
    const user = req.user || (userId && (await findUser(userId))) || null;

    const articleCount = await getArticlesByAuthor(userId);

    // If user is not logged in, redirect to login page
    if (!user) {
      return res.redirect("/auth/login");
    }

    console.log(req.body);
    // Validate if required fields are present
    if (!name || !content || !abstract || !category || !tags) {
      console.log(2222);
      return res.status(400).render("pages/CreateArticlePage", {
        title: "Tạo bài viết mới",
        errorMessage: "Vui lòng điền đầy đủ thông tin",
        tags: tagsResponse.data,
        categories: categoriesResponse.data,
        article: {
          title: "",
          author: "",
          abstract: "",
          content: "",
          is_premium: false,
        },
        user: user,
        articleCount: articleCount,
      });
    }

    // Prepare the article data for creation
    const articleData = {
      name,
      image,
      abstract,
      content,
      category,
      tags,
      isPremium,
      status,
      publishedAt,
      author: user._id, // Link article to the user
    };

    // Call the existing createArticle method
    const articleResponse = await createArticle(articleData);

    if (!articleResponse.success) {
      console.log(3333);
      return res.status(500).render("pages/CreateArticlePage", {
        title: "Tạo bài viết mới",
        errorMessage: articleResponse.error,
        tags: tagsResponse.data,
        categories: categoriesResponse.data,
        article: {
          title: "",
          author: "",
          abstract: "",
          content: "",
          is_premium: false,
        },
        user: user,
        articleCount: articleCount,
      });
    }

    // Redirect to the list of articles or the newly created article page
    res.redirect("/my-articles");
  } catch (error) {
    console.error("Create article error:", error);
    // res.status(500).render("pages/CreateArticlePage", {
    //   title: "Tạo bài viết mới",
    //   errorMessage: "Có lỗi xảy ra. Vui lòng thử lại sau.",
    //   tags: tagsResponse.data,
    //   categories: categoriesResponse.data,
    //   article: {
    //     title: "",
    //     author: "",
    //     abstract: "",
    //     content: "",
    //     is_premium: false,
    //   },
    //   user: user,
    //   articleCount: articleCount,
    // });
  }
});

export default router;
