import React, { useState, useEffect, useRef } from 'react';

const ThreatDetection = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const alertsEndRef = useRef(null);

  const BASE_URL = 'http://localhost:8000';

  // Check initial status when component mounts
  useEffect(() => {
    checkStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Set up polling for logs when scanning is active
  useEffect(() => {
    let intervalId;
    if (isScanning) {
      fetchLogs(); // Fetch immediately when scanning starts
      intervalId = setInterval(() => {
        fetchLogs();
      }, 5000); // Update logs every 5 seconds
    }
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [isScanning]);

  // Scroll to bottom when new alerts arrive
  useEffect(() => {
    if (alertsEndRef.current) {
      alertsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [alerts]);

  // Check the current status of threat detection
  const checkStatus = async () => {
    try {
      setIsLoading(true);
      const response = await fetch(`${BASE_URL}/threatdetection/status`);
      const data = await response.json();
      setIsScanning(data.status === 'running');
      setIsLoading(false);
      // If scanner is running, fetch logs immediately
      if (data.status === 'running') {
        fetchLogs();
      }
    } catch (err) {
      setError(`Error checking status: ${err.message}`);
      setIsLoading(false);
    }
  };

  // Start threat detection
  const startScan = async () => {
    try {
      setError(null);
      setIsLoading(true);
      const response = await fetch(`${BASE_URL}/threatdetection/start`, {
        method: 'POST',
      });
      const data = await response.json();
      if (response.ok) {
        setIsScanning(true);
        setAlerts([]); // Clear previous alerts when starting a new scan
      } else {
        setError(`Failed to start: ${data.message}`);
      }
      setIsLoading(false);
    } catch (err) {
      setError(`Error: ${err.message}`);
      setIsLoading(false);
    }
  };

  // Stop threat detection
  const stopScan = async () => {
    try {
      setError(null);
      setIsLoading(true);
      const response = await fetch(`${BASE_URL}/threatdetection/stop`, {
        method: 'POST',
      });
      const data = await response.json();
      if (response.ok) {
        setIsScanning(false);
        // Fetch logs one final time to get complete results
        await fetchLogs();
      } else {
        setError(`Failed to stop: ${data.message}`);
      }
      setIsLoading(false);
    } catch (err) {
      setError(`Error: ${err.message}`);
      setIsLoading(false);
    }
  };

  // Fetch logs from the server
  const fetchLogs = async () => {
    try {
      const response = await fetch(`${BASE_URL}/threatdetection/logs`);
      const data = await response.json();
      if (response.ok) {
        setAlerts(data.alerts);
        setLastUpdated(new Date());
      }
    } catch (err) {
      console.error(`Error fetching logs: ${err.message}`);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Network Threat Detection</h1>

      {/* Control Panel */}
      <div className="mb-6 p-4 border rounded-lg bg-gray-50">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold">Threat Detection Controls</h2>
            <p className="text-sm text-gray-600 mt-1">
              {isScanning
                ? 'Actively monitoring network for threats'
                : 'Start scanning to monitor network activity'}
            </p>
          </div>
          <div className="flex gap-3">
            {!isScanning ? (
              <button
                onClick={startScan}
                disabled={isLoading}
                className={`px-4 py-2 rounded ${
                  isLoading
                    ? 'bg-gray-300 cursor-not-allowed'
                    : 'bg-green-600 text-white hover:bg-green-700'
                }`}
              >
                {isLoading ? 'Loading...' : 'Start Scanning'}
              </button>
            ) : (
              <button
                onClick={stopScan}
                disabled={isLoading}
                className={`px-4 py-2 rounded ${
                  isLoading
                    ? 'bg-gray-300 cursor-not-allowed'
                    : 'bg-red-600 text-white hover:bg-red-700'
                }`}
              >
                {isLoading ? 'Loading...' : 'Stop Scanning'}
              </button>
            )}
            <button
              onClick={fetchLogs}
              disabled={isLoading || !isScanning}
              className={`px-4 py-2 rounded ${
                isLoading || !isScanning
                  ? 'bg-gray-300 cursor-not-allowed'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              Refresh Logs
            </button>
          </div>
        </div>

        {/* Scanning indicator */}
        {isScanning && (
          <div className="mt-4">
            <div className="flex items-center">
              <div className="h-3 w-3 bg-green-500 rounded-full mr-2 animate-pulse"></div>
              <span className="text-sm text-green-700 font-medium">Scanning Active</span>
            </div>
            {lastUpdated && (
              <div className="text-xs text-gray-500 mt-1">
                Last updated: {lastUpdated.toLocaleTimeString()}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Error message */}
      {error && (
        <div className="mb-6 p-3 bg-red-100 border border-red-200 text-red-700 rounded">
          {error}
        </div>
      )}

      {/* Results Panel */}
      <div className="mb-6">
        <div className="flex justify-between items-center mb-2">
          <h2 className="text-lg font-semibold">Detected Threats</h2>
          <div className="text-sm text-gray-500">
            {alerts.length} {alerts.length === 1 ? 'alert' : 'alerts'} detected
          </div>
        </div>
        <div className="border rounded-lg overflow-hidden bg-gray-50">
          <div className="h-96 overflow-y-auto p-1 bg-black">
            {alerts.length > 0 ? (
              <div className="font-mono text-sm">
                {alerts.map((alert, index) => (
                  <div
                    key={index}
                    className="py-1 px-2 text-green-400 border-b border-gray-800"
                  >
                    {typeof alert === 'string' ? alert : JSON.stringify(alert)}
                  </div>
                ))}
                <div ref={alertsEndRef} />
              </div>
            ) : (
              <div className="p-6 text-center text-gray-500">
                {isScanning
                  ? 'No threats detected yet. Monitoring network...'
                  : 'Start scanning to detect threats.'}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatDetection;