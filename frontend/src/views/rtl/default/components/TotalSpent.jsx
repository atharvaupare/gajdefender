import React, { useState } from "react";
import { motion } from "framer-motion";
import Card from "components/card";

const TotalSpent = () => {
  const [fileName, setFileName] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanReady, setScanReady] = useState(false);

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setLoading(true);
    setFileName(file.name);

    // Simulate loading (you can replace with actual API call)
    setTimeout(() => {
      setLoading(false);
      setScanReady(true);
    }, 1500);
  };

  const handleScan = () => {
    if (!scanReady) return;
    alert("File scanned: " + fileName); // Replace with actual scan logic
  };

  return (
    <Card extra="!p-[20px] text-center">
      <div className="mb-6 text-xl font-bold text-navy-700 dark:text-white">
        Upload single file
      </div>

      <label className="text-black mb-4 inline-block cursor-pointer rounded-lg bg-gray-200 px-4 py-2 text-sm hover:bg-gray-300">
        Upload File
        <input
          type="file"
          accept=".exe,.dll,.pdf,.txt"
          onChange={handleFileUpload}
          className="hidden"
        />
      </label>

      {loading && (
        <motion.div
          className="border-t-transparent mx-auto mt-4 h-8 w-8 animate-spin rounded-full border-4 border-blue-500"
          animate={{ rotate: 360 }}
          transition={{ repeat: Infinity, duration: 1, ease: "linear" }}
        />
      )}

      {fileName && !loading && (
        <div className="mt-2 text-sm text-gray-600">Uploaded: {fileName}</div>
      )}

      <button
        className={`mt-6 rounded-lg px-5 py-2 text-white transition-all duration-300 ${
          scanReady
            ? "bg-blue-600 hover:bg-blue-700"
            : "cursor-not-allowed bg-gray-400"
        }`}
        disabled={!scanReady}
        onClick={handleScan}
      >
        Scan
      </button>
    </Card>
  );
};

export default TotalSpent;
