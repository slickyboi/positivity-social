import React, { useState } from 'react';
import { Box, Card, Typography, Button, Grid, CircularProgress } from '@mui/material';
import { styled } from '@mui/material/styles';
import SentimentVerySatisfiedIcon from '@mui/icons-material/SentimentVerySatisfied';
import SentimentSatisfiedIcon from '@mui/icons-material/SentimentSatisfied';
import SentimentSatisfiedAltIcon from '@mui/icons-material/SentimentSatisfiedAlt';

const MoodButton = styled(Button)(({ theme }) => ({
  padding: theme.spacing(2),
  margin: theme.spacing(1),
  borderRadius: '15px',
  transition: 'transform 0.2s',
  '&:hover': {
    transform: 'scale(1.05)',
  },
}));

const affirmations = [
  "Today is full of possibilities!",
  "I choose to be positive and happy",
  "I'm making a difference in the world",
  "Every day is a fresh start",
  "I radiate positive energy"
];

function MoodTracker() {
  const [currentMood, setCurrentMood] = useState(null);
  const [dailyAffirmation, setDailyAffirmation] = useState(
    affirmations[Math.floor(Math.random() * affirmations.length)]
  );

  const handleMoodSelect = (mood) => {
    setCurrentMood(mood);
    // Here you would typically save this to your backend
  };

  return (
    <Box sx={{ p: 3 }}>
      <Card sx={{ p: 3, mb: 3, textAlign: 'center' }}>
        <Typography variant="h5" gutterBottom>
          Daily Affirmation
        </Typography>
        <Typography variant="h6" color="primary" sx={{ fontStyle: 'italic' }}>
          {dailyAffirmation}
        </Typography>
      </Card>

      <Card sx={{ p: 3 }}>
        <Typography variant="h5" gutterBottom>
          How are you feeling today?
        </Typography>
        <Grid container spacing={2} justifyContent="center">
          <Grid item>
            <MoodButton
              variant={currentMood === 'great' ? 'contained' : 'outlined'}
              color="primary"
              onClick={() => handleMoodSelect('great')}
              startIcon={<SentimentVerySatisfiedIcon />}
            >
              Great
            </MoodButton>
          </Grid>
          <Grid item>
            <MoodButton
              variant={currentMood === 'good' ? 'contained' : 'outlined'}
              color="primary"
              onClick={() => handleMoodSelect('good')}
              startIcon={<SentimentSatisfiedAltIcon />}
            >
              Good
            </MoodButton>
          </Grid>
          <Grid item>
            <MoodButton
              variant={currentMood === 'okay' ? 'contained' : 'outlined'}
              color="primary"
              onClick={() => handleMoodSelect('okay')}
              startIcon={<SentimentSatisfiedIcon />}
            >
              Okay
            </MoodButton>
          </Grid>
        </Grid>
      </Card>
    </Box>
  );
}

export default MoodTracker;
