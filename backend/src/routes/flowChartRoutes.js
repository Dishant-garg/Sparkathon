const express = require('express');
const router = express.Router();
const flowchartController = require('../controllers/flowChartController');

router.post('/generate', flowchartController.createFlowchart);

module.exports = router;
