import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  Card,
  CardContent,
  CardActions,
  CardMedia,
  Avatar,
  IconButton,
  ImageList,
  ImageListItem,
  Dialog,
} from '@mui/material';
import { Favorite, FavoriteBorder, AddPhotoAlternate, Edit } from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import ImageEditor from './ImageEditor';

function Feed() {
  const [posts, setPosts] = useState([]);
  const [newPost, setNewPost] = useState('');
  const [selectedImages, setSelectedImages] = useState([]);
  const [previewUrls, setPreviewUrls] = useState([]);
  const [error, setError] = useState('');
  const [editingImage, setEditingImage] = useState(null);
  const [editingImageIndex, setEditingImageIndex] = useState(null);
  const { user } = useAuth();

  const onDrop = (acceptedFiles) => {
    const newImages = acceptedFiles.filter(file => {
      if (file.size > 16 * 1024 * 1024) {
        setError('Some images were too large (max 16MB)');
        return false;
      }
      if (!file.type.startsWith('image/')) {
        setError('Some files were not images');
        return false;
      }
      return true;
    });

    setSelectedImages(prev => [...prev, ...newImages]);
    const newPreviewUrls = newImages.map(file => URL.createObjectURL(file));
    setPreviewUrls(prev => [...prev, ...newPreviewUrls]);
  };

  const { getRootProps, getInputProps } = useDropzone({
    onDrop,
    accept: {
      'image/*': []
    },
    multiple: true
  });

  useEffect(() => {
    fetchPosts();
  }, []);

  useEffect(() => {
    // Clean up preview URLs when component unmounts
    return () => {
      previewUrls.forEach(url => URL.revokeObjectURL(url));
    };
  }, [previewUrls]);

  const fetchPosts = async () => {
    try {
      const response = await axios.get('/api/posts');
      setPosts(response.data);
    } catch (err) {
      setError('Failed to fetch posts');
    }
  };

  const handleEditImage = (index) => {
    setEditingImage(previewUrls[index]);
    setEditingImageIndex(index);
  };

  const handleSaveEdit = async (editedImageBlob) => {
    const newUrl = URL.createObjectURL(editedImageBlob);
    const newPreviewUrls = [...previewUrls];
    newPreviewUrls[editingImageIndex] = newUrl;
    setPreviewUrls(newPreviewUrls);
    
    const newSelectedImages = [...selectedImages];
    newSelectedImages[editingImageIndex] = new File([editedImageBlob], selectedImages[editingImageIndex].name, {
      type: 'image/jpeg'
    });
    setSelectedImages(newSelectedImages);
    
    setEditingImage(null);
    setEditingImageIndex(null);
  };

  const handleRemoveImage = (index) => {
    URL.revokeObjectURL(previewUrls[index]);
    setPreviewUrls(prev => prev.filter((_, i) => i !== index));
    setSelectedImages(prev => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();
      formData.append('content', newPost);
      selectedImages.forEach((image, index) => {
        formData.append('images', image);
      });

      await axios.post('/api/posts', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setNewPost('');
      setSelectedImages([]);
      setPreviewUrls([]);
      fetchPosts();
    } catch (err) {
      if (err.response?.data?.error === 'Only positive content is allowed') {
        setError('Please keep your post positive and uplifting! 😊');
      } else {
        setError('Failed to create post');
      }
    }
  };

  const handleLike = async (postId) => {
    try {
      await axios.post(`/api/posts/${postId}/like`);
      fetchPosts();
    } catch (err) {
      if (err.response?.status === 401) {
        setError('Please log in to like posts');
      } else {
        setError('Failed to like post');
      }
    }
  };

  return (
    <Container maxWidth="sm" sx={{ mt: 4 }}>
      <Paper elevation={3} sx={{ p: 3, mb: 4 }}>
        <Typography variant="h6" gutterBottom>
          Share Something Positive! ✨
        </Typography>
        <form onSubmit={handleSubmit}>
          <TextField
            fullWidth
            multiline
            rows={3}
            variant="outlined"
            placeholder="What's something good that happened today?"
            value={newPost}
            onChange={(e) => setNewPost(e.target.value)}
            sx={{ mb: 2 }}
          />
          
          {previewUrls.length > 0 && (
            <ImageList sx={{ mb: 2 }} cols={3} rowHeight={164}>
              {previewUrls.map((url, index) => (
                <ImageListItem key={index}>
                  <img
                    src={url}
                    alt={`Preview ${index + 1}`}
                    loading="lazy"
                    style={{ height: '100%', objectFit: 'cover' }}
                  />
                  <Box
                    sx={{
                      position: 'absolute',
                      top: 0,
                      right: 0,
                      bgcolor: 'rgba(0, 0, 0, 0.5)',
                      borderRadius: 1,
                    }}
                  >
                    <IconButton
                      size="small"
                      onClick={() => handleEditImage(index)}
                      sx={{ color: 'white' }}
                    >
                      <Edit />
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={() => handleRemoveImage(index)}
                      sx={{ color: 'white' }}
                    >
                      ×
                    </IconButton>
                  </Box>
                </ImageListItem>
              ))}
            </ImageList>
          )}

          {error && (
            <Typography color="error" sx={{ mb: 2 }}>
              {error}
            </Typography>
          )}

          <Box sx={{ display: 'flex', gap: 2 }}>
            <Box
              {...getRootProps()}
              sx={{
                border: '2px dashed #ccc',
                borderRadius: 1,
                p: 1,
                cursor: 'pointer',
                '&:hover': { borderColor: 'primary.main' },
              }}
            >
              <input {...getInputProps()} />
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <AddPhotoAlternate />
                <Typography>Drop images or click to select</Typography>
              </Box>
            </Box>
            <Button
              type="submit"
              variant="contained"
              color="primary"
              fullWidth
            >
              Share Positivity
            </Button>
          </Box>
        </form>
      </Paper>

      {posts.map((post) => (
        <Card key={post.id} sx={{ mb: 2 }}>
          <CardContent>
            <Box display="flex" alignItems="center" mb={2}>
              <Avatar sx={{ mr: 2 }}>{post.author[0]}</Avatar>
              <Typography variant="subtitle1">{post.author}</Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 2 }}>
              {post.content}
            </Typography>
            {post.images && post.images.length > 0 && (
              <ImageList sx={{ mb: 2 }} cols={post.images.length === 1 ? 1 : 2} gap={8}>
                {post.images.map((image, index) => (
                  <ImageListItem key={index}>
                    <img
                      src={image.url}
                      alt={image.alt || `Image ${index + 1} from ${post.author}`}
                      loading="lazy"
                      style={{
                        width: '100%',
                        maxHeight: post.images.length === 1 ? '500px' : '250px',
                        objectFit: 'contain',
                      }}
                    />
                  </ImageListItem>
                ))}
              </ImageList>
            )}
            <Typography variant="caption" color="text.secondary">
              {new Date(post.timestamp).toLocaleString()}
            </Typography>
          </CardContent>
          <CardActions>
            <Button
              size="small"
              color="primary"
              onClick={() => handleLike(post.id)}
              startIcon={post.liked ? <Favorite /> : <FavoriteBorder />}
            >
              {post.likes} Likes
            </Button>
          </CardActions>
        </Card>
      ))}

      {editingImage && (
        <ImageEditor
          image={editingImage}
          open={Boolean(editingImage)}
          onClose={() => setEditingImage(null)}
          onSave={handleSaveEdit}
        />
      )}
    </Container>
  );
}

export default Feed;
