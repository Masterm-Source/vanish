import React from 'react';
import { motion } from 'framer-motion';

const LivePreview = ({ decoyData }) => {
    console.log('🎭 [LIVEPREVIEW] Component rendering with decoyData:', decoyData);
    console.log('🎭 [LIVEPREVIEW] Has decoy_content:', !!decoyData?.decoy_content);
    
    // This component is now "dumb". It only displays what it's told to.
    if (!decoyData || !decoyData.decoy_content) {
        console.log('🎭 [LIVEPREVIEW] Not rendering - no decoy content');
        return null; // Render nothing if there's no content
    }

    console.log('🎭 [LIVEPREVIEW] Rendering with content:', decoyData.decoy_content);

    return (
        <motion.div
            className="message received"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            layout
        >
            <div className="message-container">
                <div className="message-wrapper live-preview-wrapper">
                    <span className="message-text-content">{decoyData.decoy_content}</span>
                </div>
            </div>
            <div className="message-time">
                <span>{decoyData.sender_username} is typing...</span>
            </div>
        </motion.div>
    );
};

export default LivePreview;
