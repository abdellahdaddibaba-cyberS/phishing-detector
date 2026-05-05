// ============================================================
// STATE
// Central application state — all pages read/write this object
// ============================================================
const state = {
  page: 'dashboard',
  scans: [],
  historyLoaded: false,
  currentResult: null,
  historyFilter: 'all',
  historySearch: '',
  historyPage: 1,
  scanTab: 'text',
  scanText: '',
  scanUrl: '',
  scanEmail: '',
  emlFile: null,
  emlFileName: '',
  scanning: false,
  scanningStatus: '',
  apiError: null,
  settings: {
    lingWeight: 30,
    urlWeight: 40,
    suspThresh: 30,
    fishThresh: 70,
    darkMode: false,
  },
  selectedScans: new Set(),
  confirmModal: null,
  collapseState: { linguistic: true, url: true },
};

const ITEMS_PER_PAGE = 5;
