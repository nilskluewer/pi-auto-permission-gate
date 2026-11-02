// The page scripts are inlined into one <script> element in this order:
// cards.js, history.js, app.js. The first two publish a factory on window; app.js calls both.
// The page is type-checked loosely (tsconfig.page.json), so the factory contracts use `any`.
interface Window {
	createApprovalCards: (view: any) => any;
	createApprovalHistory: (view: any) => any;
}
