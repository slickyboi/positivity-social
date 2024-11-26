import React, { useState } from 'react';
import {
  Box,
  Card,
  TextField,
  Button,
  Typography,
  CircularProgress,
  Alert,
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import ImageIcon from '@mui/icons-material/Image';
import { styled } from '@mui/material/styles';

const StyledCard = styled(Card)(({ theme }) => ({
  padding: theme.spacing(3),
  marginBottom: theme.spacing(3),
  '& .MuiTextField-root': {
    marginBottom: theme.spacing(2),
  },
}));

const ImagePreview = styled('img')({
  maxWidth: '100%',
  maxHeight: '200px',
  objectFit: 'cover',
  marginTop: '10px',
  borderRadius: '8px',
});

function CreatePost() {
  const [content, setContent] = useState('');
  const [image, setImage] = useState(null);
  const [previewUrl, setPreviewUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleImageChange = (event) => {
    const file = event.target.files[0];
    if (file) {
      setImage(file);
      setPreviewUrl(URL.createObjectURL(file));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const formData = new FormData();
      formData.append('content', content);
      if (image) {
        formData.append('image', image);
      }

      const response = await fetch('http://localhost:5000/api/posts', {
        method: 'POST',
        body: formData,
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to create post');
      }

      const data = await response.json();
      setContent('');
      setImage(null);
      setPreviewUrl('');
    } catch (err) {
      setError('Failed to create post. Please try again.');
      console.error('Error creating post:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <StyledCard>
      <Typography variant="h6" gutterBottom>
        Share Something Positive
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <form onSubmit={handleSubmit}>
        <TextField
          fullWidth
          multiline
          rows={3}
          variant="outlined"
          placeholder="What's something good that happened today?"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          disabled={loading}
        />
        <input
          accept="image/*"
          type="file"
          id="image-input"
          onChange={handleImageChange}
          style={{ display: 'none' }}
        />
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <Button
            component="label"
            htmlFor="image-input"
            startIcon={<ImageIcon />}
            variant="outlined"
            disabled={loading}
          >
            Add Image
          </Button>
        </Box>
        {previewUrl && (
          <ImagePreview src={previewUrl} alt="Preview" />
        )}
        <Button
          type="submit"
          variant="contained"
          color="primary"
          fullWidth
          disabled={!content.trim() || loading}
          startIcon={loading ? <CircularProgress size={20} /> : <SendIcon />}
          sx={{ mt: 2 }}
        >
          Share Positivity
        </Button>
      </form>
    </StyledCard>
  );
}

export default CreatePost;
