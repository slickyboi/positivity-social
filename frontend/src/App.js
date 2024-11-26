import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { Box, Grid, Typography, Button, TextField, Container } from '@mui/material';
import CssBaseline from '@mui/material/CssBaseline';
import Login from './components/Login';
import Register from './components/Register';
import Feed from './components/Feed';
import Navbar from './components/Navbar';
import CreatePost from './components/CreatePost';
import MoodTracker from './components/MoodTracker';
import { AuthProvider, useAuth } from './context/AuthContext';

const theme = createTheme({
  palette: {
    primary: {
      main: '#4CAF50', // A positive green color
    },
    secondary: {
      main: '#FFC107', // Warm yellow for encouragement
    },
    background: {
      default: '#f5f5f5',
    },
  },
});

function PrivateRoute({ children }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? children : <Navigate to="/login" />;
}

function App() {
  return (
    <AuthProvider>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Router>
          <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
            <Navbar />
            <Box component="main" sx={{ flexGrow: 1, bgcolor: 'background.default', p: 3 }}>
              <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route
                  path="/"
                  element={
                    <PrivateRoute>
                      <Box sx={{ maxWidth: 1200, margin: '0 auto' }}>
                        <Grid container spacing={3}>
                          <Grid item xs={12} md={8}>
                            <CreatePost />
                            <Feed />
                          </Grid>
                          <Grid item xs={12} md={4}>
                            <MoodTracker />
                          </Grid>
                        </Grid>
                      </Box>
                    </PrivateRoute>
                  }
                />
              </Routes>
            </Box>
          </Box>
        </Router>
      </ThemeProvider>
    </AuthProvider>
  );
}

export default App;
