import React, { useRef, useState } from "react";
import { motion } from "framer-motion";
import Card from "components/card";

const TotalSpent = () => {
  const fileInputRef = useRef(null);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [processing, setProcessing] = useState(false);
  const [results, setResults] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(0);

  const handleFileChange = (e) => {
    const files = Array.from(e.target.files);
    if (files.length > 0) {
      setSelectedFiles(files);
      setResults([]);
      setCurrentIndex(0);
    }
  };

  const calculateCombinedScore = (hashData, emberData) => {
    let hashScore = 0;
    const stats = hashData?.results?.virustotal?.analysis_stats;
    if (stats) {
      const total =
        stats.harmless + stats.undetected + stats.malicious + stats.suspicious;
      hashScore = (stats.malicious / (total || 1)) * 60;
    }

    const emberScore = emberData?.score ? parseFloat(emberData.score) * 40 : 0;
    return Math.round(hashScore + emberScore);
  };

  const getScoreColor = (score) => {
    if (score <= 30) return "text-green-500";
    if (score <= 70) return "text-orange-400";
    return "text-red-500";
  };

  const getScoreBgColor = (score) => {
    if (score <= 30) return "bg-green-100";
    if (score <= 70) return "bg-orange-100";
    return "bg-red-100";
  };

  const handleScan = async () => {
    if (selectedFiles.length === 0) return;

    setProcessing(true);
    setResults([]);
    setCurrentIndex(0);

    await processFiles();
  };

  const processFiles = async () => {
    const newResults = [];

    for (let i = 0; i < selectedFiles.length; i++) {
      setCurrentIndex(i);
      const file = selectedFiles[i];

      try {
        // Update results with "processing" status for current file
        setResults((prev) => [
          ...prev,
          {
            fileName: file.name,
            fileSize: formatFileSize(file.size),
            status: "processing",
          },
        ]);

        // Step 1: Upload
        const formData = new FormData();
        formData.append("file", file);

        const uploadRes = await fetch("http://localhost:8000/files/upload", {
          method: "POST",
          body: formData,
        });

        if (!uploadRes.ok) {
          throw new Error(`Upload failed with status: ${uploadRes.status}`);
        }

        const uploadData = await uploadRes.json();
        const uploadedPath = uploadData.file_path;

        // Step 2: Hash scan
        const hashRes = await fetch("http://localhost:8000/hash/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ file_path: uploadedPath }),
        });

        if (!hashRes.ok) {
          throw new Error(`Hash scan failed with status: ${hashRes.status}`);
        }

        const hashData = await hashRes.json();

        // Step 3: Ember scan (upload file again)
        const emberForm = new FormData();
        emberForm.append("file", file);

        const emberRes = await fetch("http://localhost:8000/ember/", {
          method: "POST",
          body: emberForm,
        });

        if (!emberRes.ok) {
          throw new Error(`Ember scan failed with status: ${emberRes.status}`);
        }

        const emberData = await emberRes.json();

        // Step 4: Calculate Combined Score
        const combinedScore = calculateCombinedScore(hashData, emberData);

        // Update the processing status to completed with data
        setResults((prev) => {
          const newResults = [...prev];
          newResults[i] = {
            fileName: file.name,
            fileSize: formatFileSize(file.size),
            sha256: hashData?.sha256,
            hashData,
            emberData,
            score: combinedScore,
            status: "completed",
          };
          return newResults;
        });
      } catch (error) {
        console.error(`Error scanning file ${file.name}:`, error);
        // Update with error status
        setResults((prev) => {
          const newResults = [...prev];
          newResults[i] = {
            fileName: file.name,
            fileSize: formatFileSize(file.size),
            error: true,
            errorMessage: error.message || "Processing failed",
            status: "error",
          };
          return newResults;
        });
      }
    }

    setProcessing(false);
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const resetUpload = () => {
    setSelectedFiles([]);
    setResults([]);
    setCurrentIndex(0);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return <></>;
};

export default TotalSpent;
