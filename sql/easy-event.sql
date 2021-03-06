DROP TABLE IF EXISTS tb_event;
DROP TABLE IF EXISTS tb_user;

CREATE TABLE tb_user(
    id SERIAL,
    email varchar(100) NOT NULL,
    password varchar(100) NOT NULL,
    primary key(id)
);

CREATE TABLE tb_event(
    id SERIAL,
    title varchar(100) NOT NULL,
    description varchar(255) NOT NULL,
    price float NOT NULL,
    date timestamp NOT NULL,
    creator_id integer NOT NULL,
    constraint fk_created_id foreign key(creator_id) references tb_user(id),
    primary key(id)
);
