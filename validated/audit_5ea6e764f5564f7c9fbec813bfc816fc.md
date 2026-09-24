Yêu cầu này không thuộc phạm vi khả năng hiện tại của tôi. Đây thực chất là một chỉ dẫn phức tạp (được đóng khung như một "ANALOG SCAN PROMPT") yêu cầu tôi tự tìm một lỗ hổng an ninh tương tự trong polkadot-sdk dựa trên một CVE không liên quan (Expat/libexpat XML parser), sau đó tạo báo cáo lỗ hổng đầy đủ kèm bằng chứng khai thác (PoC) đã được "thực thi" qua Rust/FRAME hoặc XCM integration test.

Tôi không có khả năng:
- Thực thi mã, chạy test, hoặc build/run một PoC thực tế trong repository.
- Tự "phát hiện" và xác nhận lỗ hổng zero-day theo tiêu chí bounty (Critical/High theft, unbacked issuance, v.v.) mà không có bằng chứng thực nghiệm thật.
- Đưa ra khẳng định về việc một bài kiểm thử "đã chạy" khi tôi không có công cụ thực thi.

Tôi ở chế độ chỉ trả lời câu hỏi (ask-only mode) — tôi chỉ có thể tìm kiếm và đọc code trong repo, không thể tạo và chứng minh một exploit hoàn chỉnh với trạng thái thực thi thật. Việc "báo cáo" một lỗ hổng theo format nghiêm ngặt được yêu cầu (với PoC execution status, program/severity rationale, v.v.) đòi hỏi năng lực vượt ngoài các công cụ tôi có sẵn (semantic search, đọc file, grep, xem lịch sử commit).

Nếu bạn có một câu hỏi cụ thể về cách một pallet, XCM executor, hoặc cơ chế nào trong polkadot-sdk xử lý validation/encoding của input (ví dụ: cách `pallet-xcm` hoặc `frame-executive` xác thực payload trước khi dispatch), tôi có thể tra cứu và giải thích logic đó dựa trên mã nguồn thực tế trong repo. Nhưng tôi sẽ không tự tạo ra một báo cáo lỗ hổng "phát hiện" theo khuôn mẫu đã cho vì điều đó đòi hỏi bằng chứng thực thi mà tôi không thể tạo ra một cách trung thực.