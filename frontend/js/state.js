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
  scanAttachName: '',
  scanFile: null,
  scanning: false,
  apiError: null,
  settings: {
    lingWeight: 30,
    urlWeight: 40,
    attachWeight: 50,
    suspThresh: 30,
    fishThresh: 70,
    darkMode: true,
  },
  collapseState: { linguistic: true, url: true, attach: true },
};

const ITEMS_PER_PAGE = 5;
