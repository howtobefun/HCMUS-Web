import express from "express";
import {
  getArticlesByAuthor,
  getArticlesById,
} from "../../services/articleService.js";
import {
  getArticleCountByAuthor,
  getArticlesPublishedByAuthor,
} from "../../services/articleService.js";
import { createArticle, updateArticle } from "../../services/articleService.js";
import { getTags } from "../../services/tagService.js";
import { getCategories } from "../../services/categoryService.js";
import { findUserByName, findUser } from "../../services/userService.js";
import cache from "../../config/cache.js";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";

// Create __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.resolve(__dirname, "../../public", "uploads")); // Adjusted path
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage: storage });

const router = express.Router();

router.get("/", async (req, res) => {
  try {
    // Get all tags
    const tagsResponse = await getTags();

    // Get all categories
    const categoriesResponse = await getCategories();

    const userId = req.user?._id;
    const user = req.user || (userId && (await findUser(userId))) || null;

    if (!user) {
      return res.redirect("/auth/login");
    }

    // const articleCount = await getArticlesByAuthor(userId);
    const status = req.query.status || "published";
    const page = parseInt(req.query.page) || 1;
    const limit = 12;

    let articleCount;
    if (status === "published") {
      articleCount = await getArticlesPublishedByAuthor(
        userId,
        page,
        limit,
        "published"
      );
    } else if (status === "pending") {
      articleCount = await getArticlesPublishedByAuthor(
        userId,
        page,
        limit,
        "pending"
      );
    } else if (status === "draft") {
      articleCount = await getArticlesPublishedByAuthor(
        userId,
        page,
        limit,
        "draft"
      );
    } else if (status === "rejected") {
      articleCount = await getArticlesPublishedByAuthor(
        userId,
        page,
        limit,
        "rejected"
      );
    }

    const pageData = {
      title: `Writer Dashboard`,
      tags: tagsResponse.data,
      categories: categoriesResponse.data,
      articles: articleCount.data.articles,
      user: user,
      status: status,
      pagination: articleCount.data.pagination,
    };

    res.render("pages/MyPostPage", pageData);
  } catch (error) {
    console.error("My articles page error:", error);
  }
});

// GET /create

router.get("/create", async (req, res) => {
  try {
    const tagsResponse = await getTags();
    const categoriesResponse = await getCategories();

    const userId = req.user?._id;
    const user = req.user || (userId && (await findUser(userId))) || null;

    // if user is not logged in, redirect to login page
    if (!user) {
      return res.redirect("/auth/login");
    }

    const articleCount = await getArticleCountByAuthor(userId);

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

    res.render("pages/CreateArticlePage", pageData);
  } catch (error) {
    console.error("Create article page error:", error);
  }
});

router.post("/create", upload.single("image"), async (req, res) => {
  try {
    const {
      name,
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

    // If user is not logged in, redirect to login page
    if (!user) {
      return res.redirect("/auth/login");
    }

    const articleCount = await getArticlesByAuthor(userId);

    // Check if required fields are present
    if (!name || !content || !abstract || !category || !tags) {
      return res.status(400).render("pages/CreateArticlePage", {
        title: "Create New Article",
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

    // convert tags and category to array
    const tagsArray = tags.split(",");
    const categoryArray = category.split(",");

    // Handle image upload if present
    const image = req.file ? `/uploads/${req.file.filename}` : null;

    // Prepare article data
    const articleData = {
      name,
      image,
      abstract,
      content,
      tags: tagsArray,
      category: categoryArray,
      isPremium,
      status,
      publishedAt,
      author: user._id,
    };

    // Call createArticle method
    const articleResponse = await createArticle(articleData);

    if (!articleResponse.success) {
      return res.status(500).render("pages/CreateArticlePage", {
        title: "Create New Article",
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

    // Redirect after article creation
    res.redirect("/writer");
  } catch (error) {
    console.error("Create article error:", error);
    res.status(500).render("pages/CreateArticlePage", {
      title: "Tạo bài viết mới",
      errorMessage: "Có lỗi xảy ra. Vui lòng thử lại sau.",
    });
  }
});

router.get("/edit", async (req, res) => {
  try {
    const articleId = req.query.id;
    const tagsResponse = await getTags();
    const categoriesResponse = await getCategories();

    const userId = req.user?._id;
    const user = req.user || (userId && (await findUser(userId))) || null;

    if (!user) {
      return res.redirect("/auth/login");
    }

    const articleCount = await getArticleCountByAuthor(userId);

    const articleResponse = await getArticlesById(articleId);

    if (!articleResponse.success) {
      return res.status(404).render("pages/404Page", {
        title: "Không tìm thấy trang",
      });
    }

    const pageData = {
      title: "Edit Article",
      tags: tagsResponse.data,
      categories: categoriesResponse.data,
      article: articleResponse.data,
      user: user,
      articleCount: articleCount,
      rejectReason: articleResponse.data.rejectReason,
    };

    res.render("pages/EditArticlePage", pageData);
  } catch (error) {
    console.error("Edit article page error:", error);
  }
});

router.post("/edit", upload.single("image"), async (req, res) => {
  try {
    const {
      name,
      abstract,
      content,
      category,
      tags,
      isPremium,
      status,
      publishedAt,
      rejectReason,
    } = req.body;

    const articleId = req.query.id;

    const tagsResponse = await getTags();
    const categoriesResponse = await getCategories();

    const userId = req.user?._id;
    const user = req.user || (userId && (await findUser(userId))) || null;

    if (!user) {
      return res.redirect("/auth/login");
    }

    const articleCount = await getArticleCountByAuthor(userId);

    const articleResponse = await getArticlesById(articleId);

    if (!articleResponse.success) {
      return res.status(404).render("pages/404Page", {
        title: "Không tìm thấy trang",
      });
    }

    // if (articleResponse.data.author._id.toString() !== userId.toString()) {
    //   return res.status(403).render("pages/403Page", {
    //     title: "Không có quyền truy cập",
    //   });
    // }

    if (!name || !content || !abstract || !category || !tags) {
      return res.status(400).render("pages/EditArticlePage", {
        title: "Edit Article",
        errorMessage: "Vui lòng điền đầy đủ thông tin",
        tags: tagsResponse.data,
        categories: categoriesResponse.data,
        article: articleResponse.data,
        user: user,
        articleCount: articleCount,
      });
    }

    const cleanAndParseJSON = (str) => {
      try {
        // Split on closing bracket to separate JSON array from additional IDs
        const [jsonPart, ...rest] = str.split("]");

        // Parse the JSON array part
        const jsonArray = JSON.parse(jsonPart + "]");

        // Get additional IDs by cleaning up the rest
        const additionalIds = rest
          .join("")
          .split(",")
          .filter((id) => id.trim())
          .map((id) => id.trim());

        // Combine both arrays and remove duplicates
        return [...new Set([...jsonArray, ...additionalIds])];
      } catch (e) {
        // If JSON parsing fails, try splitting by comma
        return str
          .split(",")
          .filter((id) => id.trim())
          .map((id) => id.replace(/[\[\]"]/g, "").trim());
      }
    };

    const image = req.file
      ? `/uploads/${req.file.filename}`
      : articleResponse.data.image;

    const articleData = {
      name,
      image,
      abstract,
      content,
      tags: cleanAndParseJSON(tags),
      category: cleanAndParseJSON(category),
      isPremium: isPremium === "1",
      status: rejectReason ? "rejected" : "draft",
      publishedAt,
      rejectReason: status === "rejected" ? rejectReason : "",
    };

    const updateResponse = await updateArticle(articleId, articleData);
    if (!updateResponse.matchedCount) {
      return res.status(500).render("pages/EditArticlePage", {
        title: "Edit Article",
        errorMessage: updateResponse.error,
        tags: tagsResponse.data,
        categories: categoriesResponse.data,
        article: articleResponse.data,
        user: user,
        articleCount: articleCount,
      });
    }

    res.redirect("/writer");
  } catch (error) {
    console.error("Edit article error:", error);
    res.status(500).render("pages/EditArticlePage", {
      title: "Chỉnh sửa bài viết",
      errorMessage: "Có lỗi xảy ra. Vui lòng thử lại sau.",
    });
  }
});

export default router;
