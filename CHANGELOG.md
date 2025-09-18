# Changelog

## [1.1.0] - 2024-12-19

### Fixed
- **Video streaming display issue**: Fixed video elements not properly displaying remote camera streams by using img elements for data URL images instead of setting src directly on video elements
- **WebSocket connection handling**: Improved error handling and retry logic for WebSocket connections
- **Camera frame streaming**: Enhanced video frame capture and streaming with better error handling and stream management
- **Dashboard video display**: Fixed dashboard not receiving and displaying video frames from mobile devices

### Improved
- **Debug functionality**: Enhanced debug stream button with better logging and error reporting
- **Test stream functionality**: Improved test stream button to properly display test images
- **WebSocket message handling**: Better error handling for WebSocket message parsing and processing
- **Video element styling**: Improved styling for video elements when displaying remote streams

### Technical Details
- Fixed `handleRemoteVideoFrame()` function to create img elements for data URL images
- Enhanced `streamToDashboard()` function with better error handling and stream management
- Improved WebSocket connection debugging and error reporting
- Added proper cleanup for video streams and WebSocket connections

## [1.0.0] - Initial Release
- Basic camera streaming functionality
- WebSocket-based real-time communication
- Dashboard for viewing live camera feeds
- Authentication system for dashboard access
- Location sharing functionality
