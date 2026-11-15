-- Reference table for airports (IATA code, name, city, country, coordinates)
CREATE TABLE IF NOT EXISTS airports (
  iata_code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  city TEXT,
  country TEXT,
  latitude REAL NOT NULL,
  longitude REAL NOT NULL
);

-- Index for searching airports by country or city
CREATE INDEX IF NOT EXISTS idx_airports_country ON airports (country);

-- Seed common international and regional airports
INSERT OR IGNORE INTO airports (iata_code, name, city, country, latitude, longitude) VALUES
  ('ATL', 'Hartsfield-Jackson Atlanta International Airport', 'Atlanta', 'United States', 33.6367, -84.4281),
  ('LAX', 'Los Angeles International Airport', 'Los Angeles', 'United States', 33.9425, -118.4081),
  ('ORD', 'O''Hare International Airport', 'Chicago', 'United States', 41.9786, -87.9048),
  ('DFW', 'Dallas/Fort Worth International Airport', 'Dallas-Fort Worth', 'United States', 32.8968, -97.0380),
  ('DEN', 'Denver International Airport', 'Denver', 'United States', 39.8617, -104.6731),
  ('JFK', 'John F. Kennedy International Airport', 'New York', 'United States', 40.6398, -73.7789),
  ('EWR', 'Newark Liberty International Airport', 'Newark', 'United States', 40.6925, -74.1687),
  ('LGA', 'LaGuardia Airport', 'New York', 'United States', 40.7772, -73.8726),
  ('SFO', 'San Francisco International Airport', 'San Francisco', 'United States', 37.6190, -122.3748),
  ('SEA', 'Seattle-Tacoma International Airport', 'Seattle', 'United States', 47.4490, -122.3093),
  ('MIA', 'Miami International Airport', 'Miami', 'United States', 25.7932, -80.2906),
  ('BOS', 'Boston Logan International Airport', 'Boston', 'United States', 42.3643, -71.0052),
  ('IAD', 'Washington Dulles International Airport', 'Washington', 'United States', 38.9445, -77.4558),
  ('DCA', 'Ronald Reagan Washington National Airport', 'Washington', 'United States', 38.8521, -77.0377),
  ('LAS', 'Harry Reid International Airport', 'Las Vegas', 'United States', 36.0801, -115.1522),
  ('MCO', 'Orlando International Airport', 'Orlando', 'United States', 28.4294, -81.3090),
  ('PHX', 'Phoenix Sky Harbor International Airport', 'Phoenix', 'United States', 33.4343, -112.0116),
  ('IAH', 'George Bush Intercontinental Airport', 'Houston', 'United States', 29.9844, -95.3414),
  ('MSP', 'Minneapolis-Saint Paul International Airport', 'Minneapolis', 'United States', 44.8820, -93.2218),
  ('DTW', 'Detroit Metropolitan Wayne County Airport', 'Detroit', 'United States', 42.2124, -83.3534),
  ('PHL', 'Philadelphia International Airport', 'Philadelphia', 'United States', 39.8719, -75.2411),
  ('CLT', 'Charlotte Douglas International Airport', 'Charlotte', 'United States', 35.2140, -80.9431),
  ('SAN', 'San Diego International Airport', 'San Diego', 'United States', 32.7336, -117.1897),
  ('HNL', 'Daniel K. Inouye International Airport', 'Honolulu', 'United States', 21.3206, -157.9242),
  ('YYZ', 'Toronto Pearson International Airport', 'Toronto', 'Canada', 43.6772, -79.6306),
  ('YVR', 'Vancouver International Airport', 'Vancouver', 'Canada', 49.1939, -123.1844),
  ('YUL', 'Montréal-Trudeau International Airport', 'Montreal', 'Canada', 45.4706, -73.7408),
  ('MEX', 'Mexico City International Airport', 'Mexico City', 'Mexico', 19.4363, -99.0721),
  ('GRU', 'São Paulo/Guarulhos International Airport', 'São Paulo', 'Brazil', -23.4356, -46.4731),
  ('EZE', 'Ministro Pistarini International Airport', 'Buenos Aires', 'Argentina', -34.8222, -58.5358),
  ('BOG', 'El Dorado International Airport', 'Bogotá', 'Colombia', 4.7016, -74.1469),
  ('SCL', 'Arturo Merino Benítez International Airport', 'Santiago', 'Chile', -33.3930, -70.7858),
  ('LHR', 'London Heathrow Airport', 'London', 'United Kingdom', 51.4700, -0.4543),
  ('LGW', 'London Gatwick Airport', 'London', 'United Kingdom', 51.1537, -0.1821),
  ('STN', 'London Stansted Airport', 'London', 'United Kingdom', 51.8850, 0.2350),
  ('LTN', 'London Luton Airport', 'London', 'United Kingdom', 51.8747, -0.3683),
  ('LCY', 'London City Airport', 'London', 'United Kingdom', 51.5053, 0.0553),
  ('SEN', 'London Southend Airport', 'London', 'United Kingdom', 51.5714, 0.6956),
  ('BQH', 'London Biggin Hill Airport', 'London', 'United Kingdom', 51.3308, 0.0325),
  ('FAB', 'Farnborough Airport', 'Farnborough', 'United Kingdom', 51.2758, -0.7764),
  ('OXF', 'London Oxford Airport', 'Oxford', 'United Kingdom', 51.8369, -1.3200),
  ('MAN', 'Manchester Airport', 'Manchester', 'United Kingdom', 53.3537, -2.2750),
  ('BHX', 'Birmingham Airport', 'Birmingham', 'United Kingdom', 52.4539, -1.7480),
  ('BRS', 'Bristol Airport', 'Bristol', 'United Kingdom', 51.3827, -2.7191),
  ('NCL', 'Newcastle International Airport', 'Newcastle upon Tyne', 'United Kingdom', 55.0375, -1.6917),
  ('LPL', 'Liverpool John Lennon Airport', 'Liverpool', 'United Kingdom', 53.3336, -2.8497),
  ('LBA', 'Leeds Bradford Airport', 'Leeds', 'United Kingdom', 53.8659, -1.6606),
  ('EMA', 'East Midlands Airport', 'Nottingham / Derby', 'United Kingdom', 52.8311, -1.3281),
  ('SOU', 'Southampton Airport', 'Southampton', 'United Kingdom', 50.9503, -1.3568),
  ('BOH', 'Bournemouth Airport', 'Bournemouth', 'United Kingdom', 50.7800, -1.8425),
  ('EXT', 'Exeter Airport', 'Exeter', 'United Kingdom', 50.7344, -3.4139),
  ('NQY', 'Cornwall Airport Newquay', 'Newquay', 'United Kingdom', 50.4406, -4.9954),
  ('NWI', 'Norwich Airport', 'Norwich', 'United Kingdom', 52.6758, 1.2828),
  ('MME', 'Teesside International Airport', 'Darlington / Middlesbrough', 'United Kingdom', 54.5092, -1.4294),
  ('HUY', 'Humberside Airport', 'Grimsby / Hull', 'United Kingdom', 53.5744, -0.3508),
  ('BLK', 'Blackpool Airport', 'Blackpool', 'United Kingdom', 53.7717, -3.0286),
  ('GLO', 'Gloucestershire Airport', 'Gloucester / Cheltenham', 'United Kingdom', 51.8942, -2.1672),
  ('IGH', 'Isle of Wight Sandown Airport', 'Isle of Wight', 'United Kingdom', 50.6531, -1.1806),
  ('BBP', 'Bembridge Airport', 'Isle of Wight', 'United Kingdom', 50.6781, -1.1094),
  ('ISC', 'St Mary''s Airport', 'Isles of Scilly', 'United Kingdom', 49.9133, -6.2917),
  ('LEQ', 'Land''s End Airport', 'Penzance', 'United Kingdom', 50.1028, -5.6706),
  ('EDI', 'Edinburgh Airport', 'Edinburgh', 'United Kingdom', 55.9500, -3.3725),
  ('GLA', 'Glasgow Airport', 'Glasgow', 'United Kingdom', 55.8719, -4.4331),
  ('PIK', 'Glasgow Prestwick Airport', 'Prestwick', 'United Kingdom', 55.5094, -4.5867),
  ('ABZ', 'Aberdeen International Airport', 'Aberdeen', 'United Kingdom', 57.2019, -2.1978),
  ('INV', 'Inverness Airport', 'Inverness', 'United Kingdom', 57.5425, -4.0475),
  ('DND', 'Dundee Airport', 'Dundee', 'United Kingdom', 56.4525, -3.0258),
  ('KOI', 'Kirkwall Airport', 'Orkney', 'United Kingdom', 58.9578, -2.9050),
  ('LSI', 'Sumburgh Airport', 'Shetland', 'United Kingdom', 59.8789, -1.2956),
  ('SYY', 'Stornoway Airport', 'Stornoway', 'United Kingdom', 58.2156, -6.3311),
  ('BRR', 'Barra Airport', 'Barra', 'United Kingdom', 57.0228, -7.4431),
  ('TRE', 'Tiree Airport', 'Tiree', 'United Kingdom', 56.4992, -6.8692),
  ('ILY', 'Islay Airport', 'Islay', 'United Kingdom', 55.6819, -6.2567),
  ('CAL', 'Campbeltown Airport', 'Campbeltown', 'United Kingdom', 55.4372, -5.6864),
  ('BEB', 'Benbecula Airport', 'Benbecula', 'United Kingdom', 57.4811, -7.3628),
  ('WIC', 'Wick John O''Groats Airport', 'Wick', 'United Kingdom', 58.4589, -3.0931),
  ('CWL', 'Cardiff Airport', 'Cardiff', 'United Kingdom', 51.3967, -3.3433),
  ('BFS', 'Belfast International Airport', 'Belfast', 'United Kingdom', 54.6575, -6.2158),
  ('BHD', 'George Best Belfast City Airport', 'Belfast', 'United Kingdom', 54.6181, -5.8725),
  ('LDY', 'City of Derry Airport', 'Derry', 'United Kingdom', 55.0428, -7.1611),
  ('JER', 'Jersey Airport', 'Jersey', 'United Kingdom', 49.2079, -2.1955),
  ('GCI', 'Guernsey Airport', 'Guernsey', 'United Kingdom', 49.4350, -2.6020),
  ('ACI', 'Alderney Airport', 'Alderney', 'United Kingdom', 49.7061, -2.2147),
  ('IOM', 'Isle of Man Airport', 'Ronaldsway', 'United Kingdom', 54.0833, -4.6239),
  ('DUB', 'Dublin Airport', 'Dublin', 'Ireland', 53.4213, -6.2701),
  ('CDG', 'Charles de Gaulle Airport', 'Paris', 'France', 49.0097, 2.5479),
  ('ORY', 'Paris Orly Airport', 'Paris', 'France', 48.7262, 2.3652),
  ('AMS', 'Amsterdam Airport Schiphol', 'Amsterdam', 'Netherlands', 52.3086, 4.7639),
  ('FRA', 'Frankfurt Airport', 'Frankfurt', 'Germany', 50.0333, 8.5706),
  ('MUC', 'Munich Airport', 'Munich', 'Germany', 48.3538, 11.7861),
  ('BER', 'Berlin Brandenburg Airport', 'Berlin', 'Germany', 52.3667, 13.5033),
  ('HAM', 'Hamburg Airport', 'Hamburg', 'Germany', 53.6304, 9.9882),
  ('MAD', 'Adolfo Suárez Madrid–Barajas Airport', 'Madrid', 'Spain', 40.4719, -3.5626),
  ('BCN', 'Josep Tarradellas Barcelona–El Prat Airport', 'Barcelona', 'Spain', 41.2971, 2.0785),
  ('FCO', 'Leonardo da Vinci–Fiumicino Airport', 'Rome', 'Italy', 41.8003, 12.2389),
  ('MXP', 'Milan Malpensa Airport', 'Milan', 'Italy', 45.6306, 8.7281),
  ('ZRH', 'Zurich Airport', 'Zurich', 'Switzerland', 47.4647, 8.5492),
  ('GVA', 'Geneva Airport', 'Geneva', 'Switzerland', 46.2381, 6.1089),
  ('VIE', 'Vienna International Airport', 'Vienna', 'Austria', 48.1103, 16.5697),
  ('CPH', 'Copenhagen Airport', 'Copenhagen', 'Denmark', 55.6180, 12.6560),
  ('ARN', 'Stockholm Arlanda Airport', 'Stockholm', 'Sweden', 59.6519, 17.9186),
  ('OSL', 'Oslo Airport, Gardermoen', 'Oslo', 'Norway', 60.1939, 11.1004),
  ('HEL', 'Helsinki-Vantaa Airport', 'Helsinki', 'Finland', 60.3172, 24.9633),
  ('LIS', 'Humberto Delgado Airport', 'Lisbon', 'Portugal', 38.7813, -9.1359),
  ('ATH', 'Athens International Airport', 'Athens', 'Greece', 37.9364, 23.9445),
  ('IST', 'Istanbul Airport', 'Istanbul', 'Turkey', 41.2753, 28.7519),
  ('DXB', 'Dubai International Airport', 'Dubai', 'United Arab Emirates', 25.2528, 55.3644),
  ('AUH', 'Zayed International Airport', 'Abu Dhabi', 'United Arab Emirates', 24.4330, 54.6511),
  ('DOH', 'Hamad International Airport', 'Doha', 'Qatar', 25.2731, 51.6081),
  ('SIN', 'Singapore Changi Airport', 'Singapore', 'Singapore', 1.3644, 103.9915),
  ('HKG', 'Hong Kong International Airport', 'Hong Kong', 'China', 22.3080, 113.9185),
  ('HND', 'Tokyo Haneda Airport', 'Tokyo', 'Japan', 35.5494, 139.7798),
  ('NRT', 'Narita International Airport', 'Tokyo', 'Japan', 35.7647, 140.3864),
  ('KIX', 'Kansai International Airport', 'Osaka', 'Japan', 34.4272, 135.2440),
  ('ICN', 'Incheon International Airport', 'Seoul', 'South Korea', 37.4602, 126.4407),
  ('TPE', 'Taiwan Taoyuan International Airport', 'Taipei', 'Taiwan', 25.0777, 121.2328),
  ('BKK', 'Suvarnabhumi Airport', 'Bangkok', 'Thailand', 13.6811, 100.7473),
  ('KUL', 'Kuala Lumpur International Airport', 'Kuala Lumpur', 'Malaysia', 2.7456, 101.7099),
  ('DEL', 'Indira Gandhi International Airport', 'Delhi', 'India', 28.5562, 77.1000),
  ('BOM', 'Chhatrapati Shivaji Maharaj International Airport', 'Mumbai', 'India', 19.0896, 72.8656),
  ('SYD', 'Sydney Kingsford Smith Airport', 'Sydney', 'Australia', -33.9461, 151.1772),
  ('MEL', 'Melbourne Airport', 'Melbourne', 'Australia', -37.6733, 144.8433),
  ('BNE', 'Brisbane Airport', 'Brisbane', 'Australia', -27.3842, 153.1175),
  ('AKL', 'Auckland Airport', 'Auckland', 'New Zealand', -37.0082, 174.7850),
  ('JNB', 'O. R. Tambo International Airport', 'Johannesburg', 'South Africa', -26.1392, 28.2460),
  ('CPT', 'Cape Town International Airport', 'Cape Town', 'South Africa', -33.9648, 18.6017),
  ('CAI', 'Cairo International Airport', 'Cairo', 'Egypt', 30.1219, 31.4056);

-- Normalize any existing visit IATA codes to uppercase so they match airports.iata_code
UPDATE airport_visits SET iata_code = UPPER(TRIM(iata_code));

-- Ensure any IATA codes already present in airport_visits exist in airports before adding FK constraint
INSERT OR IGNORE INTO airports (iata_code, name, latitude, longitude)
SELECT DISTINCT iata_code, COALESCE(airport_name, iata_code), 0.0, 0.0
FROM airport_visits
WHERE iata_code NOT IN (SELECT iata_code FROM airports);

-- Rebuild airport_visits with Foreign Key constraints referencing airports(iata_code)
PRAGMA defer_foreign_keys = ON;

CREATE TABLE airport_visits_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  iata_code TEXT NOT NULL REFERENCES airports(iata_code) ON UPDATE CASCADE,
  airport_name TEXT,
  visit_date TEXT NOT NULL,
  username TEXT NOT NULL,
  notes TEXT,
  origin_iata TEXT REFERENCES airports(iata_code) ON UPDATE CASCADE,
  flight_number TEXT,
  distance_km REAL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO airport_visits_new (id, iata_code, airport_name, visit_date, username, notes, created_at)
SELECT id, iata_code, airport_name, visit_date, username, notes, created_at
FROM airport_visits;

DROP TABLE airport_visits;
ALTER TABLE airport_visits_new RENAME TO airport_visits;

-- Recreate indexes on the rebuilt table
CREATE INDEX IF NOT EXISTS idx_visits_date ON airport_visits (visit_date DESC);
CREATE INDEX IF NOT EXISTS idx_visits_user_date ON airport_visits (username, visit_date DESC, iata_code);
