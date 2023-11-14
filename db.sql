
CREATE TABLE `tokens` (
  `user_id` int(11) NOT NULL,
  `token` varchar(35) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ;

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `name` varchar(30) NOT NULL,
  `email` varchar(40) NOT NULL,
  `password` varchar(70) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp()
) ;

ALTER TABLE `tokens`
  ADD KEY `user_id` (`user_id`),
  ADD KEY `token` (`token`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`);

ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

ALTER TABLE `tokens`
  ADD CONSTRAINT `tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

