import React, { useState, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Slider,
  Typography,
  Box,
  Tab,
  Tabs,
} from '@mui/material';
import Cropper from 'react-easy-crop';
import { TabPanel, TabContext } from '@mui/lab';

const FILTERS = {
  none: { brightness: 100, contrast: 100, saturation: 100, sepia: 0 },
  bright: { brightness: 130, contrast: 100, saturation: 100, sepia: 0 },
  warm: { brightness: 100, contrast: 100, saturation: 120, sepia: 30 },
  cool: { brightness: 100, contrast: 110, saturation: 90, sepia: 0 },
  vintage: { brightness: 90, contrast: 120, saturation: 80, sepia: 50 },
};

function ImageEditor({ image, open, onClose, onSave }) {
  const [crop, setCrop] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [croppedArea, setCroppedArea] = useState(null);
  const [activeTab, setActiveTab] = useState('crop');
  const [selectedFilter, setSelectedFilter] = useState('none');
  const [customFilter, setCustomFilter] = useState({ ...FILTERS.none });

  const onCropComplete = useCallback((croppedAreaPercentage, croppedAreaPixels) => {
    setCroppedArea(croppedAreaPixels);
  }, []);

  const handleSave = async () => {
    try {
      // Create canvas for image processing
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const imageObj = new Image();
      
      imageObj.onload = () => {
        // Set canvas size to cropped dimensions
        canvas.width = croppedArea.width;
        canvas.height = croppedArea.height;
        
        // Draw cropped image
        ctx.drawImage(
          imageObj,
          croppedArea.x,
          croppedArea.y,
          croppedArea.width,
          croppedArea.height,
          0,
          0,
          croppedArea.width,
          croppedArea.height
        );
        
        // Apply filters
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const filters = selectedFilter === 'custom' ? customFilter : FILTERS[selectedFilter];
        
        for (let i = 0; i < imageData.data.length; i += 4) {
          // Apply brightness
          const brightness = filters.brightness / 100;
          imageData.data[i] *= brightness;
          imageData.data[i + 1] *= brightness;
          imageData.data[i + 2] *= brightness;
          
          // Apply contrast
          const contrast = ((filters.contrast - 100) * 2.55) / 100;
          imageData.data[i] += contrast;
          imageData.data[i + 1] += contrast;
          imageData.data[i + 2] += contrast;
          
          // Apply saturation
          const saturation = filters.saturation / 100;
          const gray = 0.2989 * imageData.data[i] + 0.5870 * imageData.data[i + 1] + 0.1140 * imageData.data[i + 2];
          imageData.data[i] = gray + (imageData.data[i] - gray) * saturation;
          imageData.data[i + 1] = gray + (imageData.data[i + 1] - gray) * saturation;
          imageData.data[i + 2] = gray + (imageData.data[i + 2] - gray) * saturation;
          
          // Apply sepia
          const sepiaAmount = filters.sepia / 100;
          const r = imageData.data[i];
          const g = imageData.data[i + 1];
          const b = imageData.data[i + 2];
          imageData.data[i] = Math.min(255, (r * (1 - sepiaAmount)) + ((r * 0.769 + g * 0.686 + b * 0.534) * sepiaAmount));
          imageData.data[i + 1] = Math.min(255, (g * (1 - sepiaAmount)) + ((r * 0.549 + g * 0.686 + b * 0.168) * sepiaAmount));
          imageData.data[i + 2] = Math.min(255, (b * (1 - sepiaAmount)) + ((r * 0.272 + g * 0.534 + b * 0.131) * sepiaAmount));
        }
        
        ctx.putImageData(imageData, 0, 0);
        
        // Convert to blob and save
        canvas.toBlob((blob) => {
          onSave(blob);
        }, 'image/jpeg', 0.95);
      };
      
      imageObj.src = image;
    } catch (err) {
      console.error('Error processing image:', err);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Edit Image</DialogTitle>
      <DialogContent>
        <TabContext value={activeTab}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={activeTab}
              onChange={(e, newValue) => setActiveTab(newValue)}
            >
              <Tab label="Crop" value="crop" />
              <Tab label="Filters" value="filters" />
              <Tab label="Custom" value="custom" />
            </Tabs>
          </Box>

          <TabPanel value="crop">
            <Box sx={{ position: 'relative', height: 400 }}>
              <Cropper
                image={image}
                crop={crop}
                zoom={zoom}
                aspect={16 / 9}
                onCropChange={setCrop}
                onZoomChange={setZoom}
                onCropComplete={onCropComplete}
              />
            </Box>
            <Box sx={{ mt: 2 }}>
              <Typography>Zoom</Typography>
              <Slider
                value={zoom}
                min={1}
                max={3}
                step={0.1}
                onChange={(e, value) => setZoom(value)}
              />
            </Box>
          </TabPanel>

          <TabPanel value="filters">
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              {Object.keys(FILTERS).map((filter) => (
                <Button
                  key={filter}
                  variant={selectedFilter === filter ? 'contained' : 'outlined'}
                  onClick={() => setSelectedFilter(filter)}
                >
                  {filter.charAt(0).toUpperCase() + filter.slice(1)}
                </Button>
              ))}
            </Box>
          </TabPanel>

          <TabPanel value="custom">
            <Box sx={{ mt: 2 }}>
              <Typography>Brightness</Typography>
              <Slider
                value={customFilter.brightness}
                min={0}
                max={200}
                onChange={(e, value) =>
                  setCustomFilter({ ...customFilter, brightness: value })
                }
              />
              <Typography>Contrast</Typography>
              <Slider
                value={customFilter.contrast}
                min={0}
                max={200}
                onChange={(e, value) =>
                  setCustomFilter({ ...customFilter, contrast: value })
                }
              />
              <Typography>Saturation</Typography>
              <Slider
                value={customFilter.saturation}
                min={0}
                max={200}
                onChange={(e, value) =>
                  setCustomFilter({ ...customFilter, saturation: value })
                }
              />
              <Typography>Sepia</Typography>
              <Slider
                value={customFilter.sepia}
                min={0}
                max={100}
                onChange={(e, value) =>
                  setCustomFilter({ ...customFilter, sepia: value })
                }
              />
            </Box>
          </TabPanel>
        </TabContext>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSave} variant="contained" color="primary">
          Apply Changes
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default ImageEditor;
